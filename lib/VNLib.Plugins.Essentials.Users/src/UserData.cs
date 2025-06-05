/*
* Copyright (c) 2025 Vaughn Nugent
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
using System.Threading;
using System.Threading.Tasks;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

using VNLib.Utils.Resources;
using VNLib.Plugins.Essentials.Users.Model;

namespace VNLib.Plugins.Essentials.Users
{

    /// <summary>
    /// Represents a user and its entry in the primary user table
    /// </summary>
    public sealed class UserData : ExternalResourceBase, IUser
    {
        private readonly UserEntityConfig _userConfig;
        private readonly LazyInitializer<UserExtendedFields> _properties;
        private readonly UserEntry _entry;

        private bool Disposed;

        internal UserData(UserEntityConfig handler, UserEntry entry)
        {
            _entry = entry;
            _userConfig = handler;
            _properties = new(LoadData);

            //Always undef the password hash in the entry
            entry.PassHash = null;
        }

        private UserExtendedFields LoadData()
        {
            //Recover properties from stored entity data
            UserExtendedFields? props = _userConfig.FieldSerializer.GetFields(_entry);

            if (props is null)
            {
                // Assign new object so it's never null and set the modified flag so props are written when released.
                props = new UserExtendedFields();
                Modified = true;
            }

            return props;
        }

        /// <summary>
        /// Gets the internal user entry object for the current 
        /// user data instance.
        /// </summary>
        /// <returns></returns>
        internal UserEntry GetEntryInternal() => _entry;

        ///<inheritdoc/>
        public string UserID => _entry.Id!;

        ///<inheritdoc/>
        public string EmailAddress
        {
            get => _entry.EmailAddress!;
            set
            {
                Check();
                ArgumentException.ThrowIfNullOrEmpty(value, nameof(EmailAddress));

                //Set modified flag if changed
                Modified |= _entry.EmailAddress!.Equals(value, StringComparison.OrdinalIgnoreCase);
                _entry.EmailAddress = value;
            }
        }

        ///<inheritdoc/>
        public ulong Privileges
        {
            get => (ulong)_entry.PrivilegeLevel;
            set
            {
                Check();
                //Set modified flag if changed
                Modified |= (ulong)_entry.PrivilegeLevel != value;
                _entry.PrivilegeLevel = unchecked((long)value);
            }
        }

        ///<inheritdoc/>
        public DateTimeOffset Created => _entry.Created;

        ///<inheritdoc/>
        public DateTimeOffset LastActive
        {
            get => DateTimeOffset.FromUnixTimeMilliseconds(_properties.Instance.LastActive ?? 0);
            set
            {
                long unixMs = value.ToUnixTimeMilliseconds();
                Modified |= _properties.Instance.LastActive != unixMs;
                _properties.Instance.LastActive = unixMs;
            }
        }

        ///<inheritdoc/>
        public UserStatus Status
        {
            get => (_properties.Instance.Status ?? UserStatus.Unverified);
            set
            {
                Modified |= _properties.Instance.Status != value;
                _properties.Instance.Status = value;
            }
        }

        ///<inheritdoc/>
        public bool LocalOnly
        {
            get => _properties.Instance.LocalOnly ?? false;
            set
            {
                Modified |= _properties.Instance.LocalOnly != value;
                _properties.Instance.LocalOnly = value ? true : null;
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
                return (_properties.Instance.UserStorage?.GetValueOrDefault(key)) ?? "";
            }
            set
            {
                Check();
                //If the value is null, see if the properties are null
                if (string.IsNullOrWhiteSpace(value))
                {
                    //If properties are null exit
                    if (_properties.Instance.UserStorage != null)
                    {
                        //If the value is null and properties exist, remove the entry
                        _properties.Instance.UserStorage.Remove(key);
                        Modified = true;
                    }
                }
                else
                {
                    _properties.Instance.UserStorage ??= new();
                    //Set the value
                    _properties.Instance.UserStorage[key] = value;
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
            return _properties.Instance.UserStorage?.TryGetValue(key, out string prop) == true
                ? _userConfig.ObjectSerializer.Deserialize<T>(prop)
                : default;
        }

        ///<inheritdoc/>
        public void SetObject<T>(string key, T obj)
        {
            Check();

            this[key] = obj is not null
                ? _userConfig.ObjectSerializer.Serialize(obj)
                : null;
        }

#nullable enable

        ///<inheritdoc/>
        public IEnumerator<KeyValuePair<string, string>> GetEnumerator()
        {
            Check();

            return _properties.Instance.UserStorage != null
                ? _properties.Instance.UserStorage.GetEnumerator()
                : new List<KeyValuePair<string, string>>().GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        ///<inheritdoc/>
        public void Dispose()
        {
            if (!Disposed)
            {
                _properties.Instance.UserStorage?.Clear();
                GC.SuppressFinalize(this);
                Disposed = true;
            }
        }

        ///<inheritdoc/>
        public async ValueTask ReleaseAsync(CancellationToken cancellation = default)
        {
            //If resource has already been realeased, return
            if (IsReleased)
            {
                return;
            }

            //If deleted flag is set, invoke the delete callback
            if (Deleted)
            {
                await _userConfig.OnUserDelete
                    .Invoke(_entry, cancellation)
                    .ConfigureAwait(continueOnCapturedContext: true);
            }
            //If the state has been modifed, flush changes to the store
            else if (Modified)
            {
                //Update user-data
                _userConfig.FieldSerializer.StoreFields(_entry, _properties.Instance);

                await _userConfig.OnUserUpdate
                    .Invoke(_entry, cancellation)
                    .ConfigureAwait(continueOnCapturedContext: true);
            }

            //Set the released value
            IsReleased = true;
        }

        /// <summary>
        /// Checks if the resouce has been disposed and raises an exception if it is
        /// </summary>
        /// <exception cref="ObjectDisposedException"></exception>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void Check()
        {
            if (IsReleased || Disposed)
            {
                throw new ObjectDisposedException(nameof(UserData), "This user data has already been released and cannot be used anymore.");
            }
        }
    }
}