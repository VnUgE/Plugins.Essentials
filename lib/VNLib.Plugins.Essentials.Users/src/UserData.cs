/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Users
* File: UserData.cs 
*
* UserData.cs is part of VNLib.Plugins.Essentials.Users which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Users is free software: you can redistribute it and/or modify 
* it under the terms of the GNU General Public License as published
* by the Free Software Foundation, either version 2 of the License,
* or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Users is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
* General Public License for more details.
*
* You should have received a copy of the GNU General Public License 
* along with VNLib.Plugins.Essentials.Users. If not, see http://www.gnu.org/licenses/.
*/

using System;
using System.Text.Json;
using System.Collections;
using System.Collections.Generic;
using System.Text.Json.Serialization;

using VNLib.Utils.Async;
using VNLib.Plugins.Essentials.Users.Model;
using static VNLib.Plugins.Essentials.Statics;

namespace VNLib.Plugins.Essentials.Users
{

    /// <summary>
    /// Represents a user and its entry in the primary user table
    /// </summary>
    public sealed class UserData : AsyncUpdatableResource, IUser
    {
        private sealed class UserDataObj
        {
            [JsonPropertyName("la")]
            public long? LastActive { get; set; }

            [JsonPropertyName("st")]
            public UserStatus? Status { get; set; }

            [JsonPropertyName("lo")]
            public bool? LocalOnly { get; set; }

            [JsonPropertyName("us")]
            public Dictionary<string, string>? UserStorage { get; set; }
        }

        private readonly Lazy<UserDataObj> Properties;
        internal readonly UserEntry Entry;

        ///<inheritdoc/>
        protected override IAsyncResourceStateHandler AsyncHandler { get; }

        private bool Disposed;

        internal UserData(IAsyncResourceStateHandler handler, UserEntry entry)
        {
            //Init the callbacks in async mode
            Entry = entry;
            AsyncHandler = handler;
           
            //Undef the password hash in the entry
            entry.PassHash = null;
            
            //Lazy properties
            Properties = new(LoadData, false);
        }

        private UserDataObj LoadData()
        {
            UserDataObj? props = null;
            try
            {
                //Recover properties from stream
                props = JsonSerializer.Deserialize<UserDataObj>(Entry.UserData, SR_OPTIONS) ?? new UserDataObj();
            }
            //Catch json exception for invalid data, propagate other exceptions
            catch (JsonException)
            {
                //If an exception was thrown reading back the data object, set modified flag to overwrite on release
                Modified = true;
            }
            //If props is null (or an exception is thrown, 
            return props ?? new();
        }      

        ///<inheritdoc/>
        public string UserID => Entry.Id!;

        ///<inheritdoc/>
        public string EmailAddress
        {
            get => Entry.EmailAddress!;
            set
            {
                Check();
                ArgumentException.ThrowIfNullOrEmpty(value, nameof(EmailAddress));

                //Set modified flag if changed
                Modified |= Entry.EmailAddress!.Equals(value, StringComparison.OrdinalIgnoreCase);
                Entry.EmailAddress = value;
            }
        }

        ///<inheritdoc/>
        public ulong Privileges
        {
            get => (ulong)Entry.PrivilegeLevel;
            set
            {
                Check();
                //Set modified flag if changed
                Modified |= (ulong)Entry.PrivilegeLevel != value;
                Entry.PrivilegeLevel = unchecked((long)value);
            }
        }

        ///<inheritdoc/>
        public DateTimeOffset Created => Entry.Created;

        ///<inheritdoc/>
        public DateTimeOffset LastActive
        {
            get => DateTimeOffset.FromUnixTimeMilliseconds(Properties.Value.LastActive ?? 0);
            set
            {
                long unixMs = value.ToUnixTimeMilliseconds();
                Modified |= Properties.Value.LastActive != unixMs;
                Properties.Value.LastActive = unixMs;
            }
        }

        ///<inheritdoc/>
        public UserStatus Status
        {
            get => (Properties.Value.Status ?? UserStatus.Unverified);
            set
            {
                Modified |= Properties.Value.Status != value;
                Properties.Value.Status = value;
            }
        }

        ///<inheritdoc/>
        public bool LocalOnly
        {
            get => Properties.Value.LocalOnly ?? false;
            set
            {
                Modified |= Properties.Value.LocalOnly != value;
                Properties.Value.LocalOnly = value ? true : null;
            }
        }
        

        /// <summary>
        /// Users datastore of key-value string pairs 
        /// </summary>
        /// <param name="key">Key for item in store</param>
        /// <returns>The value string if found, string.Empty otherwise</returns>
        public string this[string key]
        {
            get
            {
                Check();
                string? val = null;
                Properties.Value.UserStorage?.TryGetValue(key, out val);
                return val ?? "";
            }
            set
            {
                Check();
                //If the value is null, see if the the properties are null
                if (string.IsNullOrWhiteSpace(value))
                {
                    //If properties are null exit
                    if (Properties.Value.UserStorage != null)
                    {
                        //If the value is null and properies exist, remove the entry
                        Properties.Value.UserStorage.Remove(key);
                        Modified = true;
                    }
                }
                else
                {
                    Properties.Value.UserStorage ??= new();
                    //Set the value
                    Properties.Value.UserStorage[key] = value;
                    //Set modified flag
                    Modified = true;
                }
            }
        }

#nullable disable

        ///<inheritdoc/>
        public T GetObject<T>(string key)
        {
            Check();

            //If user storage has been definied, then try to get the value
            return Properties.Value.UserStorage?.TryGetValue(key, out string prop) == true 
                ? JsonSerializer.Deserialize<T>(prop, SR_OPTIONS) 
                : default;
        }
        
        ///<inheritdoc/>
        public void SetObject<T>(string key, T obj)
        {
            Check();

            this[key] = obj == null ? null : JsonSerializer.Serialize(obj, SR_OPTIONS);
        }

#nullable enable

        ///<inheritdoc/>
        public IEnumerator<KeyValuePair<string, string>> GetEnumerator()
        {
            Check();

            return Properties.Value.UserStorage != null 
                ? Properties.Value.UserStorage.GetEnumerator() 
                : (IEnumerator<KeyValuePair<string, string>>)new Dictionary<string, string>.Enumerator();
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
       
        ///<inheritdoc/>
        public void Dispose()
        {
            if (!Disposed)
            {
                Properties.Value.UserStorage?.Clear();
                GC.SuppressFinalize(this);
                Disposed = true;
            }
        }

        ///<inheritdoc/>
        protected override object GetResource()
        {
            //Update user-data
            Entry.UserData = JsonSerializer.SerializeToUtf8Bytes(Properties.Value, SR_OPTIONS);
            return Entry;
        }
    }
}