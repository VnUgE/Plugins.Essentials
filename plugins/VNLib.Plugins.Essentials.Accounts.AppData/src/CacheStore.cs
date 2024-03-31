/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts.AppData
* File: CacheStore.cs 
*
* CacheStore.cs is part of VNLib.Plugins.Essentials.Accounts.AppData which 
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
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;

using MemoryPack;

using VNLib.Utils.Extensions;
using VNLib.Utils.Logging;
using VNLib.Hashing.Checksums;
using VNLib.Data.Caching;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.VNCache;
using VNLib.Plugins.Extensions.VNCache.DataModel;
using VNLib.Plugins.Essentials.Accounts.AppData.Stores;
using VNLib.Plugins.Essentials.Accounts.AppData.Model;

namespace VNLib.Plugins.Essentials.Accounts.AppData
{

    [ConfigurationName("record_cache")]
    internal sealed class CacheStore : IAppDataStore
    {
        const string LogScope = "Record Cache";

        private readonly IEntityCache<RecordDataCacheEntry> _cache;
        private readonly PersistentStorageManager _backingStore;
        private readonly ILogProvider _logger;
        private readonly bool AlwaysObserverCacheUpdate;
        private readonly TimeSpan CacheTTL;


        public CacheStore(PluginBase plugin, IConfigScope config)
        {
            string cachePrefix = config.GetRequiredProperty("prefix", p => p.GetString()!);
            CacheTTL = config.GetRequiredProperty("ttl", p => p.GetTimeSpan(TimeParseType.Seconds))!;
            AlwaysObserverCacheUpdate = config.GetRequiredProperty("force_write_through", p => p.GetBoolean())!;
            _logger = plugin.Log.CreateScope(LogScope);

            //Load persistent storage manager
            _backingStore = plugin.GetOrCreateSingleton<PersistentStorageManager>();

            //Use memory pack for serialization
            MpSerializer serializer = new();

            /*
             * Initialize entity cache from the default global cache provider,
             * then create a prefixed cache for the app data records.
             * 
             * The app should make sure that the cache provider is available
             * otherwise do not load this component.
             */
            _cache = plugin.GetDefaultGlobalCache()
                ?.GetPrefixedCache(cachePrefix)
                ?.CreateEntityCache<RecordDataCacheEntry>(serializer, serializer)
                ?? throw new InvalidOperationException("No cache provider is available");

            _logger.Verbose("Cache and backing store initialized");
        }

        ///<inheritdoc/>
        public Task DeleteRecordAsync(string userId, string recordKey, CancellationToken cancellation)
        {
            /*
             * Deleting entires does not matter if they existed previously or not. Just 
             * that the opeation executed successfully. 
             * 
             * Parallelize the delete operation to the cache and the backing store
             */
            Task fromCache = _cache.RemoveAsync(GetCacheKey(userId, recordKey), cancellation);
            Task fromDb = _backingStore.DeleteRecordAsync(userId, recordKey, cancellation);

            return Task.WhenAll(fromCache, fromDb);
        }

        ///<inheritdoc/>
        public async Task<UserRecordData?> GetRecordAsync(string userId, string recordKey, RecordOpFlags flags, CancellationToken cancellation)
        {
            bool useCache = (flags & RecordOpFlags.NoCache) == 0;

            //See if caller wants to bypass cache
            if (useCache)
            {
                string cacheKey = GetCacheKey(userId, recordKey);

                //try fetching from cache
                RecordDataCacheEntry? cached = await _cache.GetAsync(cacheKey, cancellation);

                //if cache is valid, return it
                if (cached != null && !IsCacheExpired(cached))
                {
                    return new(userId, cached.RecordData, cached.UnixTimestamp, cached.Checksum);
                }
            }

            //fetch from db
            UserRecordData? stored = await _backingStore.GetRecordAsync(userId, recordKey, flags, cancellation);

            //If the record is valid and cache is enabled, update the record in cache
            if (useCache && stored is not null)
            {
                //If no checksum is present, calculate it before storing in cache
                if (!stored.Checksum.HasValue)
                {
                    ulong checksum = FNV1a.Compute64(stored.Data);
                    stored = stored with { Checksum = checksum };
                }

                //update cached version
                Task update = DeferCacheUpdate(
                    userId,
                    recordKey,
                    stored.Data,
                    stored.LastModifed,
                    stored.Checksum.Value
                );

                if (AlwaysObserverCacheUpdate || (flags & RecordOpFlags.WriteThrough) != 0)
                {
                    //Wait for cache update to complete
                    await update.ConfigureAwait(false);
                }
                else
                {
                    //Defer the cache update and continue
                    WatchDeferredCacheUpdate(update);
                }
            }

            return stored;
        }

        ///<inheritdoc/>
        public Task SetRecordAsync(string userId, string recordKey, byte[] data, ulong checksum, RecordOpFlags flags, CancellationToken cancellation)
        {

            //Always push update to db
            Task db = _backingStore.SetRecordAsync(userId, recordKey, data, checksum, flags, cancellation);

            //Optionally push update to cache
            Task cache = Task.CompletedTask;

            if ((flags & RecordOpFlags.NoCache) == 0)
            {
                long time = DateTimeOffset.Now.ToUnixTimeSeconds();

                //Push update to cache
                cache = DeferCacheUpdate(userId, recordKey, data, time, checksum);
            }

            /*
             * If writethough is not set, updates will always be deferred 
             * and this call will return immediately.
             * 
             * We still need to observe the task incase an error occurs
             */
            Task all = Task.WhenAll(db, cache);

            if (AlwaysObserverCacheUpdate || (flags & RecordOpFlags.WriteThrough) != 0)
            {
                return all;
            }
            else
            {
                WatchDeferredCacheUpdate(all);
                return Task.CompletedTask;
            }
        }

        private string GetCacheKey(string userId, string recordKey) => $"{userId}:{recordKey}";

        private bool IsCacheExpired(RecordDataCacheEntry entry)
        {
            return DateTimeOffset.FromUnixTimeSeconds(entry.UnixTimestamp).Add(CacheTTL) < DateTimeOffset.Now;
        }

        private Task DeferCacheUpdate(string userId, string recordKey, byte[] data, long time, ulong checksum)
        {
            string cacheKey = GetCacheKey(userId, recordKey);

            RecordDataCacheEntry entry = new()
            {
                Checksum = checksum,
                RecordData = data,
                UnixTimestamp = time
            };

            return _cache.UpsertAsync(cacheKey, entry);
        }

        private async void WatchDeferredCacheUpdate(Task update)
        {
            try
            {
                await update.ConfigureAwait(false);
            }
            catch (Exception e)
            {
                if (_logger.IsEnabled(LogLevel.Debug))
                {
                    _logger.Warn(e, "Failed to update cached User AppData record");
                }
                else
                {
                    _logger.Warn("Failed to update cached AppData record");
                }
            }
        }


        private sealed class MpSerializer : ICacheObjectDeserializer, ICacheObjectSerializer
        {

            public T? Deserialize<T>(ReadOnlySpan<byte> objectData)
            {
                return MemoryPackSerializer.Deserialize<T>(objectData);
            }

            public void Serialize<T>(T obj, IBufferWriter<byte> finiteWriter)
            {
                MemoryPackSerializer.Serialize(finiteWriter, obj);
            }
        }
    }
}
