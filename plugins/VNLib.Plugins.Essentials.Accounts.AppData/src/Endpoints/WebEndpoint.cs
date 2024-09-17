/*
* Copyright (c) 2024 Vaughn Nugent
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

using VNLib.Net.Http;
using VNLib.Hashing.Checksums;
using VNLib.Plugins.Essentials.Endpoints;
using VNLib.Plugins.Essentials.Extensions;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Validation;
using VNLib.Plugins.Extensions.Loading.Routing;

using VNLib.Plugins.Essentials.Accounts.AppData.Model;
using VNLib.Plugins.Essentials.Accounts.AppData.Stores;
using VNLib.Plugins.Extensions.Loading.Routing.Mvc;
using static VNLib.Plugins.Essentials.Endpoints.ResourceEndpointBase;
using static VNLib.Plugins.Essentials.Accounts.AppData.Model.HttpExtensions;

namespace VNLib.Plugins.Essentials.Accounts.AppData.Endpoints
{
    
    [EndpointLogName("Endpoint")]
    [ConfigurationName("web_endpoint")]
    internal sealed class WebEndpoint(PluginBase plugin, IConfigScope config) : IHttpController
    {
        const int DefaultMaxDataSize = 8 * 1024;

        private readonly StorageManager _store = plugin.GetOrCreateSingleton<StorageManager>();
        private readonly int MaxDataSize = config.GetValueOrDefault("max_data_size", DefaultMaxDataSize);
        private readonly string[] AllowedScopes = config.GetRequiredProperty<string[]>("allowed_scopes");

        ///<inheritdoc/>
        public ProtectionSettings GetProtectionSettings() => default;

        [HttpStaticRoute("{{path}}", HttpMethod.GET)]
        [HttpRouteProtection(AuthorzationCheckLevel.Critical)]
        public async ValueTask<VfReturnType> GetDataAsync(HttpEntity entity)
        {
            WebMessage webm = new();

            string? scopeId = GetScopeId(entity);
            bool noCache = NoCacheQuery(entity);

            if (webm.Assert(scopeId != null, "Missing scope"))
            {
                return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
            }

            if (webm.Assert(IsScopeAllowed(scopeId), "Invalid scope"))
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


        [HttpStaticRoute("{{path}}", HttpMethod.PUT)]
        [HttpRouteProtection(AuthorzationCheckLevel.Critical)]
        public async ValueTask<VfReturnType> UpdateDataAsync(HttpEntity entity)
        {
            WebMessage webm = new();
            string? scopeId = GetScopeId(entity);
            bool flush = NoCacheQuery(entity);

            if (webm.Assert(entity.Files.Count == 1, "Invalid file count"))
            {
                return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
            }

            if (webm.Assert(scopeId != null, "Missing scope"))
            {
                return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
            }

            if (webm.Assert(IsScopeAllowed(scopeId), "Invalid scope"))
            {
                return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
            }

            FileUpload data = entity.Files[0];

            if (webm.Assert(data.Length <= MaxDataSize, "Data too large"))
            {
                return VirtualClose(entity, webm, HttpStatusCode.RequestEntityTooLarge);
            }

            byte[] recordData = new byte[data.Length];
            int read = await data.FileData.ReadAsync(recordData, entity.EventCancellation);

            if (webm.Assert(read == recordData.Length, "Failed to read data"))
            {
                return VirtualClose(entity, webm, HttpStatusCode.InternalServerError);
            }

            //Compute checksum on sent data and compare to the header if it exists
            ulong checksum = FNV1a.Compute64(recordData);
            ulong? userChecksum = GetUserDataChecksum(entity.Server);

            if (userChecksum.HasValue)
            {
                //compare the checksums
                if (webm.Assert(checksum == userChecksum.Value, "Checksum mismatch"))
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

        [HttpStaticRoute("{{path}}", HttpMethod.DELETE)]
        [HttpRouteProtection(AuthorzationCheckLevel.Critical)]
        public async ValueTask<VfReturnType> DeleteDataAsync(HttpEntity entity)
        {
            WebMessage webm = new();
            string? scopeId = GetScopeId(entity);

            if (webm.Assert(scopeId != null, "Missing scope"))
            {
                return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
            }

            if (webm.Assert(IsScopeAllowed(scopeId), "Invalid scope"))
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
        {
            return AllowedScopes.Contains(scopeId, StringComparer.OrdinalIgnoreCase);
        }

        private static string? GetScopeId(HttpEntity entity) 
            => entity.QueryArgs.GetValueOrDefault("scope");

        private static bool NoCacheQuery(HttpEntity entity) 
            => entity.QueryArgs.ContainsKey("no_cache");
    }
}
