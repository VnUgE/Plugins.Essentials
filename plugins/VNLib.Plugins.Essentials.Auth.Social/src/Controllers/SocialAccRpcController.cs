/*
* Copyright (c) 2025 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Auth.Social
* File: SocialAccRpcController.cs 
*
* SocialAccRpcController.cs is part of VNLib.Plugins.Essentials.Auth.Social which 
* is part of the larger VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Auth.Social is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Auth.Social is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Text.Json;
using System.Collections.Frozen;
using System.Text.Json.Serialization;

using FluentValidation;

using RestSharp;

using VNLib.Utils.Logging;
using VNLib.Net.Http;
using VNLib.Hashing.IdentityUtility;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Validation;
using VNLib.Plugins.Essentials.Accounts;
using VNLib.Plugins.Essentials.Extensions;
using VNLib.Plugins.Essentials.Accounts.AccountRpc;
using VNLib.Plugins.Essentials.Users;
using VNLib.Plugins.Extensions.Loading.Users;

namespace VNLib.Plugins.Essentials.Auth.Social.Controllers
{
    [ServiceExport]
    [ConfigurationName("social_oauth")]
    public sealed class SocialAccRpcController(PluginBase plugin, IConfigScope config) : IAccountRpcController
    {
        private readonly ILogProvider Log = plugin.Log.CreateScope("SocialAccRpcController");
        private readonly SocialOauthConfigJson Config = config.DeserialzeAndValidate<SocialOauthConfigJson>();
        private readonly SocialMethodLoader _loader = plugin.GetOrCreateSingleton<SocialMethodLoader>();
        private readonly IUserManager Users = plugin.GetOrCreateSingleton<UserManager>();

        ///<inheritdoc/>
        public IAccountRpcMethod[] GetMethods()
        {
            if (!Config.Enabled)
            {
                Log.Information("Social OAuth login is disabled via config, no methods will be loaded");
                return [];
            }

            Log.Verbose("Loading social OAuth methods");

            //Load all enabled methods from config
            ISocialOauthMethod[] methods = _loader.LoadAllMethods();
            if (methods.Length == 0)
            {
                Log.Warn("No social OAuth methods were loaded, social OAuth login will be disabled");
                return [];
            }

            FrozenDictionary<string, ISocialOauthMethod> methodMap = methods
                .ToFrozenDictionary(static m => m.MethodName, static m => m);

            return [new OnGetMethods(this, methodMap)];
        }
        
        private sealed class OnGetMethods(
            SocialAccRpcController _controller,
            FrozenDictionary<string, ISocialOauthMethod> _methods
        ) : IAccountRpcMethod
        {
            private static readonly string[] supported_procedures = [ "upgrade", "authenticate", "logout" ];

            private readonly JsonDocument EmptyDoc = JsonDocument.Parse("{}");
            private readonly UpgradeValidator _validator = new();
            private readonly SocialAuthStateManager _authUtil = new(_controller.Config);

            private readonly SingleCookieController _upgradeCookie = new (
                Name: _controller.Config.UpgradeCookieName, 
                TimeSpan.FromSeconds(_controller.Config.UpgradeTimeoutSec)
            )
            {
                Path        = "/",
                HttpOnly    = true,
                SameSite    = CookieSameSite.Strict,
                Secure      = true,
            };

            ///<inheritdoc/>
            public string MethodName => "social_oauth";

            ///<inheritdoc/>
            public RpcMethodOptions Flags => RpcMethodOptions.None;

            ///<inheritdoc/>
            public async ValueTask<object?> OnUserGetAsync(HttpEntity entity)
            {
                MethodData[] mData = new MethodData[_methods.Count];

                //Get data for each method
                for (int i = 0; i < mData.Length; i++)
                {
                    ISocialOauthMethod method = _methods.Values[i];
                    object? data = await method.OnGetInfo(entity);

                    mData[i] = new MethodData
                    {
                        Supported   = true,
                        Id          = method.MethodName,
                        Data        = data
                    };
                }

                return new
                {
                    type = "social_oauth",
                    methods = mData,
                    supported_procedures
                };
            }

            ///<inheritdoc/>
            public async ValueTask<RpcCommandResult> InvokeAsync(HttpEntity entity, AccountJRpcRequest message, JsonElement request)
            {
                WebMessage webm = new();

                if (webm.AssertError(IsCorsValid(entity), "Origin is not allowed"))
                {
                    _controller.Log.Debug("Request was denied because it's origin is now allowed");
                    return RpcCommandResult.Error(HttpStatusCode.Forbidden, webm);
                }

                //Get the procuder name
                if (
                    !request.TryGetProperty("procedure", out JsonElement procEl)
                    || procEl.ValueKind != JsonValueKind.String
                )
                {
                    webm.AssertError(false, "Missing or invalid procedure name");
                    return RpcCommandResult.Error(HttpStatusCode.BadRequest, webm);
                }


                //Try to get procedure arguments from the request
                if (
                    !request.TryGetProperty("args", out JsonElement fnArgs)
                    && fnArgs.ValueKind == JsonValueKind.Object
                )
                {
                    fnArgs = EmptyDoc.RootElement;
                }

                ValueTask<RpcCommandResult> result;

                switch (procEl.GetString())
                {
                    case "logout":
                        result = LogoutAsync(entity);
                        break;

                    case "upgrade":
                        result = InitUpgradeAsync(entity, fnArgs);
                        break;

                    case "authenticate":
                        result = AuthenticateCodeAsync(entity, fnArgs);
                        break;

                    default:
                        webm.AssertError(false, "The selected method does not support the requested procedure");
                        return RpcCommandResult.Error(HttpStatusCode.BadRequest, webm);
                }

                //Invoke method and return the result
                return await result.ConfigureAwait(false);
            }

            private async ValueTask<RpcCommandResult> LogoutAsync(HttpEntity entity)
            {
                WebMessage webm = new();

                /*
                * If a connection is not properly authorized to modify the session
                * we can invalidate the client by detaching the session. This 
                * should cause the session to remain in tact but the client will
                * be detached.
                * 
                * This prevents attacks where connection with just a stolen session 
                * id can cause the client's session to be invalidated. 
                */

                if (entity.IsClientAuthorized(AuthorzationCheckLevel.Critical))
                {
                    //perform logout for the authenticated method
                    string? methodId = _authUtil.GetAuthenticatedMethod(entity);

                    _controller.Log.Verbose("Logging out of social oauth method {MethodId}", methodId);

                    if (!string.IsNullOrWhiteSpace(methodId))
                    {
                        if (_methods.TryGetValue(methodId, out ISocialOauthMethod? method))
                        {
                            SocialMethodState state = new()
                            {
                                Entity      = entity,
                                Users       = _controller.Users,
                                MethodId    = methodId
                            };

                            webm.Result = await method.OnLogoutAsync(state, EmptyDoc.RootElement);
                        }
                    }
                    else
                    {
                        //Method was not used, so perform a normal deauth for the client
                        entity.InvalidateLogin();
                    }
                }
                else
                {
                    //Detatch the session to cause client only invalidation
                    entity.Session.Detach();
                }

                return RpcCommandResult.Okay(webm);
            }

            private async ValueTask<RpcCommandResult> InitUpgradeAsync(HttpEntity entity, JsonElement args)
            {
                WebMessage webm = new();

                //An upgrade cannot be issued if the user is already logged in
                bool isLoggedIn = entity.IsClientAuthorized(AuthorzationCheckLevel.Any);
                if (webm.AssertError(!isLoggedIn, "You are already logged in"))
                {
                    return RpcCommandResult.Error(HttpStatusCode.Conflict, webm);
                }

                ClientUpgradeJson? upgrade = args.Deserialize<ClientUpgradeJson>();
                if(webm.AssertError(upgrade is not null, "Missing procedure arguments structure"))
                {
                    return RpcCommandResult.Error(HttpStatusCode.BadRequest, webm);
                }

                if(!_validator.Validate(upgrade, webm))
                {
                    return RpcCommandResult.Error(HttpStatusCode.UnprocessableEntity, webm);
                }

                if (!_methods.TryGetValue(upgrade.MethodId, out ISocialOauthMethod? method))
                {
                    webm.AssertError(false, "The selected method does not exist");
                    return RpcCommandResult.Error(HttpStatusCode.BadRequest, webm);
                }

                //Invalidate a pre-existing upgrade
                _authUtil.ClearUpgrade(entity);

                SocialMethodState state = new()
                {
                    Entity      = entity,
                    Users       = _controller.Users,
                    MethodId    = upgrade.MethodId
                };

                SocialUpgradeResult result = await method.OnUpgradeAsync(state, args);
                if (!result.Success)
                {
                    webm.AssertError(false, "The upgrade request failed");
                    return RpcCommandResult.Error(HttpStatusCode.BadRequest, webm);
                }

                //Get the upgrade token and set the client's upgrade cookie
                string upgradeData = _authUtil.CreateClientUpgrade(
                    entity, 
                    methodId: method.MethodName, 
                    secInfo: upgrade, 
                    userData: result.StateData
                );

                _upgradeCookie.SetCookie(entity, upgradeData);

                return RpcCommandResult.Okay(new UpgradeResponse
                {
                    Token = upgradeData,
                    AuthenticationUrl = result.AuthUrl,
                });
            }

            private async ValueTask<RpcCommandResult> AuthenticateCodeAsync(HttpEntity entity, JsonElement args)
            {
                WebMessage webm = new();

                //An upgrade cannot be issued if the user is already logged in
                bool isLoggedIn = entity.IsClientAuthorized(AuthorzationCheckLevel.Any);
                if (webm.AssertError(!isLoggedIn, "You are currently logged in, cannot continue"))
                {
                    return RpcCommandResult.Error(HttpStatusCode.Conflict, webm);
                }

                try
                {
                    //Get the upgrade token from the client's cookie
                    string? upgrade = _upgradeCookie.GetCookie(entity);
                    if (webm.AssertError(!string.IsNullOrWhiteSpace(upgrade), "Missing upgrade token"))
                    {
                        return RpcCommandResult.Error(HttpStatusCode.BadRequest, webm);
                    }

                    using JsonWebToken upgradeJwt = JsonWebToken.Parse(upgrade);

                    bool signatureValid = _authUtil.IsUpgradeSignatureValid(entity, upgradeJwt);
                    if (webm.AssertError(signatureValid, "Your authorization token is not valid"))
                    {
                        return RpcCommandResult.Error(HttpStatusCode.BadRequest, webm);
                    }

                    using JsonDocument upgradeDocument = upgradeJwt.GetPayload();
                    if(webm.AssertError(_authUtil.IsUpgradeValid(entity, upgradeDocument), "Your authorization token is not valid"))
                    {
                        return RpcCommandResult.Error(HttpStatusCode.BadRequest, webm);
                    }

                    //Recover the security info object, and also get the user-specific data json element
                    ClientUpgradeJson secInfo = _authUtil.GetSecInfo<ClientUpgradeJson>(upgradeDocument)!;
                    JsonElement userStateDatEl = _authUtil.GetUserDataElement(upgradeDocument);
                    string methodId = _authUtil.GetMethodId(upgradeDocument);

                    if (!_methods.TryGetValue(methodId, out ISocialOauthMethod? method))
                    {
                        webm.AssertError(false, "The selected method does not exist");
                        return RpcCommandResult.Error(HttpStatusCode.BadRequest, webm);
                    }

                    SocialMethodState state = new()
                    {
                        Entity      = entity,
                        Users       = _controller.Users,
                        MethodId    = method.MethodName
                    };

                    object? result = await method.OnAuthenticateAsync(state, secInfo, args, userStateDatEl);                    
                    if (webm.AssertError(result is not null, "The authentication request failed"))
                    {
                        return RpcCommandResult.Error(HttpStatusCode.BadRequest, webm);
                    }

                    //Assign the authenticated method assuming autentication was successful
                    _authUtil.SetAuthenticatedMethod(entity, method.MethodName);

                    return RpcCommandResult.Okay(result);
                }
                catch(FormatException fe)
                {
                    _controller.Log.Debug("Failed to parse upgrade token", fe);
                    webm.AssertError(false, "Failed to parse upgrade token");
                }
                finally
                {
                    //Always remove the upgrade cookie after an authentication attempt, users must restart the process
                    _upgradeCookie.ExpireCookie(entity);
                }

                return RpcCommandResult.Error(HttpStatusCode.BadRequest, webm);
            }

            private bool IsCorsValid(HttpEntity entity)
            {
                if (!entity.Server.CrossOrigin)
                {
                    return true;
                }

                //Connection is cross origin, check if the origin is allowed

                //deny all cors connections
                if (_controller.Config.DenyCorsConnections)
                {
                    return false;
                }

                if (_controller.Config.AllowAllCorsConnections)
                {
                    return true;
                }

                //Get the connection's origin authority and ensure it is in the allowed list
                string? originAuthority = entity.Server.Origin?.GetLeftPart(UriPartial.Authority);

                return _controller.Config.AllowedCorsOrigins.Contains(originAuthority, StringComparer.OrdinalIgnoreCase);
            }
         

            private sealed class UpgradeResponse
            {
                [JsonPropertyName("auth_url")]
                public string? AuthenticationUrl { get; set; }

                [JsonPropertyName("token")]
                public string? Token { get; set; }
            }

            private sealed class MethodData
            {
                [JsonPropertyName("supported")]
                public required bool Supported { get; set; }

                [JsonPropertyName("method_id")]
                public required string Id { get; set; }

                [JsonPropertyName("data")]
                public required object? Data { get; set; }
            }
            private sealed class ClientUpgradeJson : IClientSecInfo
            {
                [JsonPropertyName("method_id")]
                public string MethodId { get; init; } = null!;

                [JsonPropertyName("pubkey")]
                public string PublicKey { get; init; } = null!;

                [JsonPropertyName("clientid")]
                public string ClientId { get; init; } = null!;
            }

            private sealed class UpgradeValidator: AbstractValidator<ClientUpgradeJson>
            {
                public UpgradeValidator()
                {
                    RuleFor(c => c.MethodId)
                        .NotEmpty()
                        .Matches(@"^[\w\-.]+$");

                    RuleFor(c => c.PublicKey)
                        .NotEmpty()
                        //base64 string under 4096 bytes
                        .Matches(@"^[a-zA-Z0-9+/]{1,4096}={0,2}$");

                    //Hex string under 64 characters
                    RuleFor(c => c.ClientId)
                        .NotEmpty()
                        .Matches(@"^[a-fA-F0-9]{1,64}$");
                }
            }
        }
    }
}
