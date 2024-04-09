/*
* Copyright (c) 2024 Vaughn Nugent
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

using Microsoft.EntityFrameworkCore;

using VNLib.Utils.Logging;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Sql;
using VNLib.Plugins.Extensions.Data;
using VNLib.Plugins.Extensions.Data.Abstractions;
using VNLib.Plugins.Extensions.Data.Extensions;
using VNLib.Plugins.Essentials.Accounts.AppData.Model;

namespace VNLib.Plugins.Essentials.Accounts.AppData.Stores.Sql
{

    internal sealed class SqlBackingStore(PluginBase plugin) : IAppDataStore, IAsyncConfigurable
    {
        private readonly DbRecordStore _store = new(plugin.GetContextOptionsAsync());

        ///<inheritdoc/>
        async Task IAsyncConfigurable.ConfigureServiceAsync(PluginBase plugin)
        {
            //Wait for the options to be ready
            await _store.WhenLoaded();

            //Add startup delay
            await Task.Delay(2000);

            plugin.Log.Debug("Creating database tables for Account AppData");

            await plugin.EnsureDbCreatedAsync<UserRecordDbContext>(plugin);
        }

        ///<inheritdoc/>
        public Task DeleteRecordAsync(string userId, string recordKey, CancellationToken cancellation)
        {
            return _store.DeleteAsync([userId, recordKey], cancellation);
        }

        ///<inheritdoc/>
        public async Task<UserRecordData?> GetRecordAsync(string userId, string recordKey, RecordOpFlags flags, CancellationToken cancellation)
        {
            DataRecord? dr = await _store.GetSingleAsync(userId, recordKey);

            if (dr is null)
            {
                return null;
            }

            //get the last modified time in unix time for the caller
            long lastModifed = new DateTimeOffset(dr.LastModified).ToUnixTimeSeconds();

            return new(userId, dr.Data!, lastModifed, unchecked((ulong)dr.Checksum));
        }

        ///<inheritdoc/>
        public Task SetRecordAsync(string userId, string recordKey, byte[] data, ulong checksum, RecordOpFlags flags, CancellationToken cancellation)
        {
            return _store.AddOrUpdateAsync(new DataRecord
            {
                UserId = userId,
                RecordKey = recordKey,
                Data = data,
                Checksum = unchecked((long)checksum)
            }, cancellation);
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
                existing.Data = newRecord.Data;
                existing.Checksum = newRecord.Checksum;
                existing.RecordKey = newRecord.RecordKey;
                existing.UserId = newRecord.UserId;
                existing.Created = newRecord.Created;
            }

            sealed class DbQueries : IDbQueryLookup<DataRecord>
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

       
    }
}
