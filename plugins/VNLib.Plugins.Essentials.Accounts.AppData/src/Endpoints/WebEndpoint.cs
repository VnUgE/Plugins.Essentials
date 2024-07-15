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

using System.Net;
using System.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;

using VNLib.Net.Http;
using VNLib.Hashing.Checksums;
using VNLib.Plugins.Essentials.Endpoints;
using VNLib.Plugins.Essentials.Extensions;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Validation;

using VNLib.Plugins.Essentials.Accounts.AppData.Model;
using VNLib.Plugins.Essentials.Accounts.AppData.Stores;

namespace VNLib.Plugins.Essentials.Accounts.AppData.Endpoints
{
    [ConfigurationName("web_endpoint")]
    internal sealed class WebEndpoint : ProtectedWebEndpoint
    {
        const int DefaultMaxDataSize = 8 * 1024;

        private readonly StorageManager _store;
        private readonly int MaxDataSize;
        private readonly string[] AllowedScopes;

        public WebEndpoint(PluginBase plugin, IConfigScope config)
        {
            string path = config.GetRequiredProperty<string>("path");
            InitPathAndLog(path, plugin.Log.CreateScope("Endpoint"));

            MaxDataSize = config.GetValueOrDefault("max_data_size", DefaultMaxDataSize);
            AllowedScopes = config.GetRequiredProperty<string[]>("allowed_scopes");
         
            _store = plugin.GetOrCreateSingleton<StorageManager>();
        }

        protected async override ValueTask<VfReturnType> GetAsync(HttpEntity entity)
        {
            WebMessage webm = new();

            string? scopeId = entity.QueryArgs.GetValueOrDefault("scope");
            bool noCache = entity.QueryArgs.ContainsKey("no_cache");

            if (webm.Assert(scopeId != null, "Missing scope"))
            {
                return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
            }

            if (webm.Assert(AllowedScopes.Contains(scopeId), "Invalid scope"))
            {
                return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
            }

            //If the connection has the no-cache header set, also bypass the cache
            noCache |= entity.Server.NoCache();

            //optionally bypass cache if the user requests it
            RecordOpFlags flags = noCache ? RecordOpFlags.NoCache : RecordOpFlags.None;

            UserRecordData? record = await _store.GetRecordAsync(entity.Session.UserID, scopeId, flags, entity.EventCancellation);

            if (record is null)
            {
                return VirtualClose(entity, webm, HttpStatusCode.NotFound);
            }

            //return the raw data with the checksum header
            entity.SetRecordResponse(record, HttpStatusCode.OK);
            return VfReturnType.VirtualSkip;
        }

        protected override async ValueTask<VfReturnType> PutAsync(HttpEntity entity)
        {
            WebMessage webm = new();
            string? scopeId = entity.QueryArgs.GetValueOrDefault("scope");
            bool flush = entity.QueryArgs.ContainsKey("flush");

            if (webm.Assert(entity.Files.Count == 1, "Invalid file count"))
            {
                return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
            }

            if (webm.Assert(scopeId != null, "Missing scope"))
            {
                return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
            }

            if (webm.Assert(AllowedScopes.Contains(scopeId), "Invalid scope"))
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
            ulong? userChecksum = entity.Server.GetUserDataChecksum();

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
            await _store.SetRecordAsync(entity.Session.UserID, scopeId, recordData, checksum, flags, entity.EventCancellation);
            return VirtualClose(entity, HttpStatusCode.Accepted);
        }

        protected override async ValueTask<VfReturnType> DeleteAsync(HttpEntity entity)
        {
            WebMessage webm = new();
            string? scopeId = entity.QueryArgs.GetValueOrDefault("scope");

            if (webm.Assert(scopeId != null, "Missing scope"))
            {
                return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
            }

            if (webm.Assert(AllowedScopes.Contains(scopeId), "Invalid scope"))
            {
                return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
            }

            //Write the record to the store
            await _store.DeleteRecordAsync(entity.Session.UserID, scopeId, entity.EventCancellation);
            return VirtualClose(entity, HttpStatusCode.Accepted);
        }
    }
}
