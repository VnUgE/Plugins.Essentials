/*
* Copyright (c) 2025 Vaughn Nugent
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
using System.IO;
using System.Diagnostics;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using System.Text.Json.Serialization;

using MemoryPack;

using VNLib.Hashing;
using VNLib.Utils.Logging;
using VNLib.Data.Caching;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Essentials.Accounts.AppData.Model;
using VNLib.Plugins.Essentials.Accounts.AppData.Stores.Sql;
using VNLib.Plugins.Extensions.VNCache;
using VNLib.Plugins.Extensions.VNCache.DataModel;

namespace VNLib.Plugins.Essentials.Accounts.AppData.Stores
{
    [ConfigurationName("storage")]
    internal sealed class StorageManager : IAppDataStore
    {
        private readonly SqlBackingStore _backingStore;
        private readonly EntityResultCache<UserRecordData>? _cache;
        private readonly ILogProvider _logger;

        public StorageManager(PluginBase plugin, IConfigScope config)
        {
            string storeType = config.GetRequiredProperty<string>("type").ToLower(null);

            _logger = plugin.Log.CreateScope("STORE");

            switch (storeType)
            {
                case "sql":
                    _backingStore = plugin.GetOrCreateSingleton<SqlBackingStore>();
                    plugin.Log.Information("Using SQL based backing store");
                    break;
                default:
                    throw new NotSupportedException($"Storage type {storeType} is not supported");
            }

            CacheConfig? cConfig = config.GetValueOrDefault<CacheConfig?>("cache", defaultValue: null);

            if (cConfig is null || !cConfig.Enabled)
            {
                _logger.Information("Result cache disabled via configuration, or not set");
                return;
            }

            ICacheClient? cache = plugin.GetDefaultGlobalCache();

            if (cache is null)
            {
                _logger.Warn("Cache was enabled, but no global cache library was loaded. Caching disabled");
                return;
            }

            /*
             * When using a shared global cache, prefixing keys is important to avoid
             * key collisions with other plugins. It is also a security measure to prevent
             * other systems from reading senstive data with any type of key injection
             * from other systems like sessions, or reading sessions from this plugin 
             * and so on.
             * 
             * A static prefix should be used and shared between servers for optimal
             * cache performance. If a prefix is not set, a random prefix will be generated
             * and logged to the console.
             */
            if (string.IsNullOrWhiteSpace(cConfig.Prefix))
            {
                cConfig.Prefix = RandomHash.GetRandomBase32(8);
                _logger.Warn("CACHE: No prefix was set, using random prefix: {prefix}", cConfig.Prefix);
            }

            MpSerializer serializer = new();
            MpCachePolicy expPolicy = new(TimeSpan.FromSeconds(cConfig.CacheTTL));

            ICacheTaskPolicy cacheTaskPolicy = cConfig.WriteBack
                ? new WriteBackCachePolicy(OnTaskError)
                : WriteThroughCachePolicy.Instance;

            _cache = cache
                .GetPrefixedCache(cConfig.Prefix)
                .CreateEntityCache<UserRecordData>(serializer, serializer)
                .CreateResultCache()
                .WithExpirationPoicy(expPolicy)
                .WithTaskPolicy(cacheTaskPolicy)
                .Build();
        }

        public Task DeleteRecordAsync(string userId, string recordKey, CancellationToken cancellation)
        {
            AppDataRequest adr = new (userId, recordKey);

            //Attempt to purge from cache and store in parallel if cache is enabled
            Task cacheDel = _cache is not null
                ? _cache.RemoveAsync(userId, cancellation)
                : Task.CompletedTask;

            Task storeRemove = _backingStore.RemoveAsync(adr, cancellation);

            return Task.WhenAll(cacheDel, storeRemove);
        }

        ///<inheritdoc/>
        public Task<UserRecordData?> GetRecordAsync(string userId, string recordKey, RecordOpFlags flags, CancellationToken cancellation)
        {
            AppDataRequest adr = new(userId, recordKey);

            //If cache is disabled, or the NoCache flag is set, bypass the cache
            if (_cache is null || (flags & RecordOpFlags.NoCache) > 0)
            {
                return _backingStore.GetAsync(adr, cancellation);
            }

            return _cache.FetchAsync(
                request: adr,
                resultFactory: _backingStore.GetAsync,
                cancellation
            );
        }

        ///<inheritdoc/>
        public Task SetRecordAsync(string userId, string recordKey, byte[] data, ulong checksum, RecordOpFlags flags, CancellationToken cancellation)
        {
            AppDataRequest adr = new (userId, recordKey);

            UserRecordData record = new ()
            {
                Data            = data,
                Checksum        = checksum,

                /*
                 * Cache upsert should set this to the current time. Set to 0 to force expire by default
                 * The database does not map this value so it doesn't matter for the backing store
                 */
                CacheTimestamp  = 0
            };

            //If cache is disabled, or the NoCache flag is set, bypass the cache
            if (_cache is null || (flags & RecordOpFlags.NoCache) > 0)
            {
                return _backingStore.UpsertAsync(adr, record, cancellation);
            }

            return _cache.UpsertAsync(
                request: adr,
                entity: record,
                action: _backingStore.UpsertAsync,
                cancellation
            );
        }

        private void OnTaskError(Task update)
        {
            try
            {
                update.GetAwaiter().GetResult();
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

            ///<inheritdoc/>
            public T? Deserialize<T>(ReadOnlySpan<byte> objectData)
                => MemoryPackSerializer.Deserialize<T>(objectData);

            ///<inheritdoc/>
            public void Serialize<T>(T obj, Stream outputStream)
            {
                /*
                 * When FBM is used, the output stream is a specialized stream that
                 * implements IBufferWriter<byte> to allow for more efficient buffer
                 * access. This is ideally a temporary solution until a better 
                 * serializer interface can be implemented in the client libraries.
                 */
                if (outputStream is IBufferWriter<byte> writer)
                {
                    MemoryPackSerializer.Serialize(in writer, in obj);
                }
                else
                {
                    /*
                     * The stream passed should be a MemoryStream or similar that supports
                     * synchronous writes. So it should be safe to synchronously wait on 
                     * the returned task. Ideally this funciton should never block and 
                     * always return IsCompleted. If were wrong, then converting it to 
                     * as Task and awaiting it will work for now.
                     */

                    ValueTask asAsync = MemoryPackSerializer.SerializeAsync(outputStream, obj);

                    if (asAsync.IsCompleted)
                    {
                        asAsync.GetAwaiter()
                            .GetResult();
                    }
                    else
                    {
                        Trace.WriteLine("Blocking on async serialize operation, this should not happen in production code");

                        asAsync.AsTask()
                            .GetAwaiter()
                            .GetResult();
                    }
                }
            }
        }

        private sealed class MpCachePolicy(TimeSpan CacheTTL) : ICacheExpirationPolicy<UserRecordData>
        {
            ///<inheritdoc/>
            public bool IsExpired(UserRecordData result)
            {
                DateTimeOffset timestamp = DateTimeOffset.FromUnixTimeSeconds(result.CacheTimestamp);

                return timestamp.Add(CacheTTL) > DateTimeOffset.UtcNow;
            }

            ///<inheritdoc/>
            public void OnRefreshed(UserRecordData entity)
            {
                //Store current utc timestamp on entity before its stored in cache again
                entity.CacheTimestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            }
        }

        private sealed class CacheConfig
        {
            [JsonPropertyName("enabled")]
            public bool Enabled { get; set; } = true;

            [JsonPropertyName("ttl")]
            public long CacheTTL { get; set; } = 120;    //max age in seconds

            [JsonPropertyName("force_write_back")]
            public bool WriteBack { get; set; } = false;

            [JsonPropertyName("prefix")]
            public string? Prefix { get; set; }
        }
    }
}
