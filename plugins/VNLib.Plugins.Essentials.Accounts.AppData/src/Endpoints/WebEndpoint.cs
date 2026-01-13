/*
* Copyright (c) 2026 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts.AppData
* File: WebEndpoint.cs 
*
* WebEndpoint.cs is part of VNLib.Plugins.Essentials.Accounts.AppData which 
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

using System;
using System.Net;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text.Json.Serialization;

using VNLib.Net.Http;
using VNLib.Hashing.Checksums;
using VNLib.Plugins.Essentials.Endpoints;
using VNLib.Plugins.Essentials.Extensions;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Validation;
using VNLib.Plugins.Extensions.Loading.Routing;
using VNLib.Plugins.Extensions.Loading.Routing.Mvc;

using FluentValidation;

using VNLib.Plugins.Essentials.Accounts.AppData.Model;
using VNLib.Plugins.Essentials.Accounts.AppData.Stores;
using static VNLib.Plugins.Essentials.Endpoints.ResourceEndpointBase;
using static VNLib.Plugins.Essentials.Accounts.AppData.Model.HttpExtensions;

namespace VNLib.Plugins.Essentials.Accounts.AppData.Endpoints
{

    [EndpointLogName("Endpoint")]
    [ConfigurationName("web_endpoint")]
    internal sealed class WebEndpoint(PluginBase plugin, IConfigScope config) : IHttpController
    {
        private readonly StorageManager _store = plugin.GetOrCreateSingleton<StorageManager>();
        private readonly EndpointConfigJson _config = config.DeserialzeAndValidate<EndpointConfigJson>();

        ///<inheritdoc/>
        public ProtectionSettings GetProtectionSettings() => default;

        [HttpStaticRoute("{{ path }}", HttpMethod.GET)]
        [HttpRouteProtection(AuthorzationCheckLevel.Critical)]
        public async ValueTask<VfReturnType> GetDataAsync(HttpEntity entity)
        {
            WebMessage webm = new();

            string? scopeId = GetScopeId(entity);
            bool noCache = NoCacheQuery(entity);

            if (webm.AssertError(scopeId != null, "Missing scope"))
            {
                return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
            }

            if (webm.AssertError(IsScopeAllowed(scopeId), "Invalid scope"))
            {
                return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
            }

            //If the connection has the no-cache header set, also bypass the cache
            noCache |= entity.Server.NoCache();

            UserRecordData? record = await _store.GetRecordAsync(
                entity.Session.UserID,
                recordKey: scopeId,
                flags: noCache ? RecordOpFlags.NoCache : RecordOpFlags.None,   //optionally bypass cache if the user requests it
                entity.EventCancellation
            );

            //return the raw data with the checksum header

            return record is null
                ? VirtualClose(entity, webm, HttpStatusCode.NotFound)
                : CloseWithRecord(entity, record, HttpStatusCode.OK);
        }


        [HttpStaticRoute("{{ path }}", HttpMethod.PUT)]
        [HttpRouteProtection(AuthorzationCheckLevel.Critical)]
        public async ValueTask<VfReturnType> UpdateDataAsync(HttpEntity entity)
        {
            WebMessage webm = new();
            string? scopeId = GetScopeId(entity);
            bool flush = NoCacheQuery(entity);

            if (webm.AssertError(entity.Files.Count == 1, ["Invalid file count"]))
            {
                return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
            }

            if (webm.AssertError(scopeId != null, ["Missing scope"]))
            {
                return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
            }

            if (webm.AssertError(IsScopeAllowed(scopeId), ["Invalid scope"]))
            {
                return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
            }

            FileUpload data = entity.Files[0];

            if (webm.AssertError(data.Length <= _config.MaxDataSize, ["Data too large"]))
            {
                return VirtualClose(entity, webm, HttpStatusCode.RequestEntityTooLarge);
            }

            byte[] recordData = GC.AllocateUninitializedArray<byte>((int)data.Length, pinned: false);
            int read = await data.FileData.ReadAsync(recordData, entity.EventCancellation);

            if (webm.AssertError(read == recordData.Length, ["Failed to read data"]))
            {
                return VirtualClose(entity, webm, HttpStatusCode.InternalServerError);
            }

            //Compute checksum on sent data and compare to the header if it exists
            ulong checksum = FNV1a.Compute64(recordData);
            ulong? userChecksum = GetUserDataChecksum(entity.Server);

            if (userChecksum.HasValue)
            {
                //compare the checksums
                if (webm.AssertError(checksum == userChecksum.Value, ["Checksum mismatch"]))
                {
                    return VirtualClose(entity, webm, HttpStatusCode.UnprocessableEntity);
                }
            }

            /*
             * If the user specifies the flush flag, the call will wait until the entire record
             * is published to the persistent store before returning. Typically if a caching layer is 
             * used, the record will be written to the cache and the call will return immediately.
             */
            RecordOpFlags flags = flush ? RecordOpFlags.WriteThrough : RecordOpFlags.None;

            //Write the record to the store
            await _store.SetRecordAsync(
                userId: entity.Session.UserID,
                recordKey: scopeId,
                recordData,
                checksum,
                flags,
                entity.EventCancellation
            );

            return VirtualClose(entity, HttpStatusCode.Accepted);
        }

        [HttpStaticRoute("{{ path }}", HttpMethod.DELETE)]
        [HttpRouteProtection(AuthorzationCheckLevel.Critical)]
        public async ValueTask<VfReturnType> DeleteDataAsync(HttpEntity entity)
        {
            WebMessage webm = new();
            string? scopeId = GetScopeId(entity);

            if (webm.AssertError(scopeId != null, ["Missing scope"]))
            {
                return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
            }

            if (webm.AssertError(IsScopeAllowed(scopeId), ["Invalid scope"]))
            {
                return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
            }

            //Write the record to the store
            await _store.DeleteRecordAsync(
                userId: entity.Session.UserID,
                recordKey: scopeId,
                entity.EventCancellation
            );

            return VirtualClose(entity, HttpStatusCode.Accepted);
        }

        private bool IsScopeAllowed(string scopeId) 
            => _config.AllowedScopes.Contains(scopeId, StringComparer.OrdinalIgnoreCase);

        private static string? GetScopeId(HttpEntity entity)
            => entity.QueryArgs.GetValueOrDefault("scope");

        private static bool NoCacheQuery(HttpEntity entity)
            => entity.QueryArgs.ContainsKey("no_cache");

        /// <summary>
        /// Configuration model for the web endpoint with validation rules
        /// </summary>
        private sealed class EndpointConfigJson : IOnConfigValidation
        {
            /// <summary>
            /// Maximum allowed size for uploaded data in bytes. Must be between 1 and 65536.
            /// Defaults to 8KB.
            /// </summary>
            [JsonPropertyName("max_data_size")]
            public int MaxDataSize { get; set; } = 8 * 1024;

            /// <summary>
            /// Array of allowed scope identifiers that clients can access.
            /// Scope IDs must be non-empty and contain no whitespace.
            /// </summary>
            [JsonPropertyName("allowed_scopes")]
            public string[] AllowedScopes { get; set; } = [];

            public void OnValidate()
            {
                InlineValidator<EndpointConfigJson> validator = [];

                validator.RuleFor(x => x.MaxDataSize)
                    .InclusiveBetween(1, 64 * 1024)
                    .WithMessage("Config property 'max_data_size' must be between 1 and 65536 bytes");

                validator.RuleFor(x => x.AllowedScopes)
                    .NotNull()
                    .WithMessage("Config property 'allowed_scopes' must not be empty");

                validator.RuleForEach(x => x.AllowedScopes)
                    .NotEmpty()
                    .WithMessage("Config property 'allowed_scopes' contains a null or empty string")
                    .Matches(@"^\S+$")
                    .WithMessage("Config property 'allowed_scopes' contains an invalid scope id");

                validator.ValidateAndThrow(this);
            }
        }
    }
}
