/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: AccountRpcEndpoint.cs 
*
* AccountRpcEndpoint.cs is part of VNLib.Plugins.Essentials.Accounts which 
* is part of the larger VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Accounts is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Accounts is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

using System.Net;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Text.Json.Serialization;

using FluentValidation;

using VNLib.Utils;
using VNLib.Utils.Logging;
using VNLib.Net.Http;
using VNLib.Plugins.Essentials.Endpoints;
using VNLib.Plugins.Essentials.Extensions;
using VNLib.Plugins.Essentials.Sessions;
using VNLib.Plugins.Extensions.Validation;
using VNLib.Plugins.Extensions.Loading;
using static VNLib.Plugins.Essentials.Statics;
using VNLib.Plugins.Essentials.Accounts.AccountRpc;
using VNLib.Plugins.Extensions.Loading.Routing.Mvc;

/*
  * Password only log-ins should be immune to repeat attacks on the same backend, because sessions are 
  * guarunteed to be mutally exclusive on the same system, therefor a successful login cannot be repeated
  * without a logout with the proper authorization.
  * 
  * Since MFA upgrades are indempodent upgrades can be regenerated continually as long as the session 
  * is not authorized, however login authorizations should be immune to repeats because session locking
  * 
  * Session id's are also regenerated per request, the only possible vector could be stale session cache
  * that has a valid MFA key and an old, but valid session id.
  */

namespace VNLib.Plugins.Essentials.Accounts.Endpoints
{
    [ConfigurationName("rpc")]
    internal sealed class AccountRpcEndpoint : IHttpController
    {
        private static readonly IValidator<AccountJRpcRequest> AccountJRpcValidator = BuildRequestValidator();
        private static readonly JsonDocument EmptyDoc = JsonDocument.Parse("{}");

        private readonly AccountRpcLoader _rpcManager;
        private readonly FrozenDictionary<string, IAccountRpcMethod> _methodTable;
        private readonly RpcMethodGetJson[] _getMethodJsonArray;

        public AccountRpcEndpoint(PluginBase plugin)
        {
            _rpcManager = plugin.GetOrCreateSingleton<AccountRpcLoader>();

            //Load all rpc methods into a dictionary for the plugin
            _methodTable = _rpcManager
                .LoadAllMethods()
                .ToFrozenDictionary(
                    static m => m.MethodName,
                    static m => m
                );

            _getMethodJsonArray = _methodTable.Values
                .Select(static method => new RpcMethodGetJson
                {
                    Method      = method.MethodName,
                    Options     = GetOptionsForMethod(method)
                })
                .ToArray();

            plugin.Log.CreateScope("RPC Endpoint")
                .Verbose("RPC methods: {methods}", _methodTable.Select(static p => p.Key));
        }

        private static string[] GetOptionsForMethod(IAccountRpcMethod method)
        {
            return method.Flags == RpcMethodOptions.AuthRequired
                ? (["auth_required"])
                : ([]);
        }

        ///<inheritdoc/>
        public ProtectionSettings GetProtectionSettings() => default;

        [HttpStaticRoute("{{path}}", HttpMethod.GET)]
        [HttpRouteProtection(AuthorzationCheckLevel.None, AllowNewSession = false, SessionType = SessionType.Web)]
        public async ValueTask<VfReturnType> OnGetAsync(HttpEntity entity)
        {
            RpcGetResponse req = new()
            {
                AllowedMethods      = [ "POST", "GET" ],
                ContentType         = HttpHelpers.GetContentTypeString(ContentType.Json),
                RpcMethods          = _getMethodJsonArray,
            };

            //Fetch get results from all methods to extend the response
            foreach (IAccountRpcMethod method in _methodTable.Values)
            {
                object? getResult = await method.OnUserGetAsync(entity);

                if (getResult is not null)
                {
                    req.ExtendedProperties.Add(getResult);
                }
            }

            return ResourceEndpointBase.VirtualCloseJson(entity, req, HttpStatusCode.OK);
        }

        /*
         * The main RPC endpoint for all account related operations. This endpoint is used to
         * process all account related operations, such as login, logout, password changes, and so on.
         */

        [HttpStaticRoute("{{path}}", HttpMethod.POST)]
        [HttpRouteProtection(AuthorzationCheckLevel.None, AllowNewSession = false, SessionType = SessionType.Web)]
        public async ValueTask<VfReturnType> OnPostAsync(HttpEntity entity)
        {
            //Ensure the client accepts json responses
            if (!entity.Server.Accepts(ContentType.Json))
            {
                //406 Not Acceptable
                entity.CloseResponse(HttpStatusCode.NotAcceptable);
                return VfReturnType.VirtualSkip;
            }

            RpcResponseMessage response = new();

            //Ensure the user sent a file in the request (entity body is required for jRPC)
            if (response.Assert(entity.Files.Count > 0, "Missing request entity body"))
            {
                return Error(entity, HttpStatusCode.BadRequest, response);
            }

            //Ensure json request content type
            bool isJson = entity.Files[0].ContentType == ContentType.Json;
            if (response.Assert(isJson, "Invalid content type"))
            {
                return Error(entity, HttpStatusCode.UnsupportedMediaType, response);
            }

            //Ensure account security is enabled
            if (response.Assert(entity.RequestedRoot.AccountSecurity != null, "Account security is not enabled"))
            {
                return Error(entity, HttpStatusCode.Forbidden, response);
            }

            //Recover the json document from the file
            using JsonDocument? request = await entity.GetJsonFromFileAsync();
            if (response.Assert(request != null, "Invalid request data"))
            {
                return Error(entity, HttpStatusCode.BadRequest, response);
            }

            AccountJRpcRequest? methodReq = request.Deserialize<AccountJRpcRequest>(SR_OPTIONS);
            if (response.Assert(methodReq != null, "Invalid request data"))
            {
                return Error(entity, HttpStatusCode.BadRequest, response);
            }

            //Assign the method and id to the response so it can be sent back to the client
            response.Method = methodReq.Method;
            response.Id     = methodReq.Id;

            //validate the rpc request
            if (!AccountJRpcValidator.Validate(methodReq, response))
            {
                return Error(entity, HttpStatusCode.UnprocessableEntity, response);
            }

            if (!_methodTable.TryGetValue(methodReq.Method!, out IAccountRpcMethod? method))
            {
                response.Result = "The requested rpc method does not exit";
                return Error(entity, HttpStatusCode.NotFound, response);
            }

            //See if authorization is required for this method
            if (RequiresAuth(method))
            {
                bool isAuthorized = entity.IsClientAuthorized(AuthorzationCheckLevel.Critical);

                if (response.Assert(isAuthorized, "You are not logged in"))
                {
                    return Error(entity, HttpStatusCode.Unauthorized, response);
                }
            }

            //Try to get the data object from the request
            if (!request.RootElement.TryGetProperty("data", out JsonElement requestArgs))
            {
                requestArgs = EmptyDoc.RootElement;
            }

            //Invoke the rpc method
            RpcCommandResult result = await method.InvokeAsync(entity, methodReq, requestArgs);

            //Mirror result if the callee returns a webmessage object
            if (result.Response is WebMessage webm)
            {
                response.Success    = webm.Success;
                response.Result     = webm.Result;
                response.Token      = webm.Token;
                response.Errors     = webm.Errors;
            }
            else
            {
                response.Success = result.Status == 0;
                response.Result = result.Response;
            }

            /*
             * If a status code is returned (not succesful) then return the error
             */
            return result.Status > 0
                ? Error(entity, result.Status, response)
                : Okay(entity, response);
        }


        private static bool RequiresAuth(IAccountRpcMethod method)
            => (method.Flags & RpcMethodOptions.AuthRequired) > 0;

        private static VfReturnType Error(HttpEntity entity, HttpStatusCode code, RpcResponseMessage msg)
        {
            //Mirror status code
            msg.StatusCode = (int)code;
            return ResourceEndpointBase.VirtualCloseJson(entity, msg, code);
        }

        private static VfReturnType Error(HttpEntity entity, ERRNO code, RpcResponseMessage msg)
        {
            //Mirror status code
            msg.StatusCode = (int)code;
            return ResourceEndpointBase.VirtualCloseJson(entity, msg, (HttpStatusCode)(int)code);
        }

        private static VfReturnType Okay(HttpEntity entity, RpcResponseMessage msg)
            => Error(entity, code: 200, msg);

        private static IValidator<AccountJRpcRequest> BuildRequestValidator()
        {
            InlineValidator<AccountJRpcRequest> val = new();

            val.RuleFor(r => r.Method)
                .NotEmpty()
                .Matches(@"^[\w\-.]+$")
                .Length(1, 100);

            val.RuleFor(r => r.Version)
                .NotEmpty()
                //must match version number
                .Matches(@"^\d+\.\d+\.\d+$");

            val.RuleFor(r => r.Id)
                .NotEmpty()
                .Matches(@"^[\w\-.]+$")
                .Length(1, 100);

            return val;
        }

        private sealed class RpcResponseMessage : WebMessage
        {
            [JsonPropertyName("id")]
            public string? Id { get; set; }

            [JsonPropertyName("method")]
            public string? Method { get; set; }

            [JsonPropertyName("code")]
            public int StatusCode { get; set; }
        }

        private sealed class RpcGetResponse
        {
            [JsonPropertyName("http_methods")]
            public required string[] AllowedMethods { get; set; }

            [JsonPropertyName("rpc_methods")]
            public required RpcMethodGetJson[] RpcMethods { get; set; }

            [JsonPropertyName("accept_content_type")]
            public required string ContentType { get; set; }

            [JsonPropertyName("properties")]
            public List<object> ExtendedProperties { get; set; } = [];
        }

        private sealed class RpcMethodGetJson
        {
            [JsonPropertyName("method")]
            public required string Method { get; set; }

            [JsonPropertyName("options")]
            public required string[] Options { get; set; }
        }
    }
}