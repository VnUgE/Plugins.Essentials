/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts.AppData
* File: PersistentStorageManager.cs 
*
* PersistentStorageManager.cs is part of VNLib.Plugins.Essentials.Accounts.AppData which 
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
using System.Threading;
using System.Threading.Tasks;

using VNLib.Utils.Logging;
using VNLib.Plugins.Extensions.Loading;

using VNLib.Plugins.Essentials.Accounts.AppData.Model;
using VNLib.Plugins.Essentials.Accounts.AppData.Stores.Sql;

namespace VNLib.Plugins.Essentials.Accounts.AppData.Stores
{
    [ConfigurationName("storage")]
    internal sealed class PersistentStorageManager : IAppDataStore
    {
        private readonly IAppDataStore _backingStore;

        public PersistentStorageManager(PluginBase plugin, IConfigScope config)
        {
            string storeType = config.GetRequiredProperty("type", p => p.GetString()!).ToLower(null);

            switch (storeType)
            {
                case "sql":
                    _backingStore = plugin.GetOrCreateSingleton<SqlBackingStore>();
                    plugin.Log.Information("Using SQL based backing store");
                    break;
                default:
                    throw new NotSupportedException($"Storage type {storeType} is not supported");
            }
        }

        ///<inheritdoc/>
        public Task DeleteRecordAsync(string userId, string recordKey, CancellationToken cancellation)
        {
            return _backingStore.DeleteRecordAsync(userId, recordKey, cancellation);
        }

        ///<inheritdoc/>
        public Task<UserRecordData?> GetRecordAsync(string userId, string recordKey, RecordOpFlags flags, CancellationToken cancellation)
        {
            return _backingStore.GetRecordAsync(userId, recordKey, flags, cancellation);
        }

        ///<inheritdoc/>
        public Task SetRecordAsync(string userId, string recordKey, byte[] data, ulong checksum, RecordOpFlags flags, CancellationToken cancellation)
        {
            return _backingStore.SetRecordAsync(userId, recordKey, data, checksum, flags, cancellation);
        }
    }
}
