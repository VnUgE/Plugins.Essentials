/*
* Copyright (c) 2025 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts.AppData
* File: SqlBackingStore.cs 
*
* SqlBackingStore.cs is part of VNLib.Plugins.Essentials.Accounts.AppData which 
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
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Text.Json.Serialization;

using Microsoft.EntityFrameworkCore;

using VNLib.Utils;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Sql;
using VNLib.Plugins.Extensions.Data;
using VNLib.Plugins.Extensions.Data.Abstractions;
using VNLib.Plugins.Extensions.Data.Extensions;
using VNLib.Plugins.Extensions.VNCache.DataModel;

using VNLib.Plugins.Essentials.Accounts.AppData.Model;


namespace VNLib.Plugins.Essentials.Accounts.AppData.Stores.Sql
{

    [ConfigurationName("storage")] // Use the global storage config section
    internal sealed class SqlBackingStore(PluginBase plugin, IConfigScope config)
        : IEntityStore<UserRecordData, AppDataRequest>, IAsyncConfigurable
    {
        private readonly DbRecordStore _store = new(plugin.GetContextOptionsAsync());
        private readonly SqlStorageConfigJson _config = config.DeserialzeAndValidate<SqlStorageConfigJson>();

        ///<inheritdoc/>
        async Task IAsyncConfigurable.ConfigureServiceAsync(PluginBase plugin)
        {
            if (_config.RunDbInit)
            {
                //Add startup delay
                await Task.Delay(2000);
                await plugin.EnsureDbCreatedAsync<UserRecordDbContext>(plugin);
            }
        }

        ///<inheritdoc/>
        public async Task<UserRecordData?> GetAsync(AppDataRequest request, CancellationToken cancellation = default)
        {
            DataRecord? dr = await _store.GetSingleAsync([request.UserId, request.RecordKey]);

            if (dr is null || !string.Equals(dr.UserId, request.UserId, StringComparison.Ordinal))
            {
                return null;
            }

            //get the last modified time in unix time for the caller
            long lastModifed = new DateTimeOffset(dr.LastModified).ToUnixTimeSeconds();

            return new()
            {
                Data            = dr.Data,
                CacheTimestamp  = lastModifed,
                Checksum        = dr.Checksum == 0 ? null : unchecked((uint)dr.Checksum)
            };
        }

        ///<inheritdoc/>
        public Task UpsertAsync(AppDataRequest request, UserRecordData entity, CancellationToken cancellation = default)
        {
            return _store.AddOrUpdateAsync(new DataRecord
            {
                UserId      = request.UserId,
                RecordKey   = request.RecordKey,
                Data        = entity.Data,
                Checksum    = entity.Checksum.HasValue ? unchecked((long)entity.Checksum.Value) : 0,

            }, cancellation);
        }

        ///<inheritdoc/>
        public async Task<bool> RemoveAsync(AppDataRequest request, CancellationToken cancellation = default)
        {
            ERRNO result = await _store
                .DeleteAsync([request.UserId, request.RecordKey], cancellation)
                .ConfigureAwait(false);

            return result > 0;
        }


        sealed class DbRecordStore(IAsyncLazy<DbContextOptions> options) : DbStore<DataRecord>
        {
            public async Task WhenLoaded() => await options;

            ///<inheritdoc/>
            public override IDbQueryLookup<DataRecord> QueryTable { get; } = new DbQueries();

            ///<inheritdoc/>
            public override IDbContextHandle GetNewContext() => new UserRecordDbContext(options.Value);

            ///<inheritdoc/>
            public override string GetNewRecordId() => Guid.NewGuid().ToString("N");

            ///<inheritdoc/>
            public override void OnRecordUpdate(DataRecord newRecord, DataRecord existing)
            {
                existing.Data       = newRecord.Data;
                existing.Checksum   = newRecord.Checksum;
                existing.RecordKey  = newRecord.RecordKey;
                existing.UserId     = newRecord.UserId;
                existing.Created    = newRecord.Created;
            }

            private sealed class DbQueries : IDbQueryLookup<DataRecord>
            {
                public IQueryable<DataRecord> GetCollectionQueryBuilder(IDbContextHandle context, params string[] constraints)
                {
                    throw new NotSupportedException("Lists for users is not queryable. Callers must submit a record key");
                }

                public IQueryable<DataRecord> GetSingleQueryBuilder(IDbContextHandle context, params string[] constraints)
                {
                    string userId = constraints[0];
                    string recordKey = constraints[1];

                    return from r in context.Set<DataRecord>()
                           where r.UserId == userId && r.RecordKey == recordKey
                           select r;
                }

                public IQueryable<DataRecord> AddOrUpdateQueryBuilder(IDbContextHandle context, DataRecord record)
                {
                    return GetSingleQueryBuilder(context, record.UserId!, record.RecordKey!);
                }
            }
        }

        private sealed class SqlStorageConfigJson : StorageConfigJson
        {
            /// <summary>
            /// Gets or sets a value indicating whether the database should be initialized
            /// on startup. Defaults to true.
            /// </summary>
            [JsonPropertyName("run_db_init")]
            public bool RunDbInit { get; init; } = true;        
        }
    }
}
