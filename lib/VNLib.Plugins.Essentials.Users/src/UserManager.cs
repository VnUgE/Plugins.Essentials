﻿/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Users
* File: UserManagerExport.cs 
*
* UserManagerExport.cs is part of VNLib.Plugins.Essentials.Users which is part of the larger 
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
using System.Data;
using System.Linq;
using System.Threading;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

using Microsoft.EntityFrameworkCore;

using VNLib.Hashing;
using VNLib.Utils;
using VNLib.Utils.Async;
using VNLib.Utils.Memory;
using VNLib.Plugins.Essentials.Accounts;
using VNLib.Plugins.Essentials.Users.Model;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Sql;
using VNLib.Plugins.Extensions.Loading.Users;

namespace VNLib.Plugins.Essentials.Users
{

    /// <summary>
    /// Provides SQL database backed structured user accounts 
    /// </summary>
    [ServiceExport]
    [ConfigurationName("users", Required = false)]
    public sealed class UserManager : IUserManager, IAsyncResourceStateHandler
    {
        private const int DefaultRandomPasswordLength = 128;

        private readonly IAsyncLazy<DbContextOptions> _dbOptions;
        private readonly IPasswordHashingProvider _passwords;
        private readonly int _randomPasswordLength = DefaultRandomPasswordLength;

        public UserManager(PluginBase plugin)
        {
            //Get the connection factory
            _dbOptions = plugin.GetContextOptionsAsync();

            //Load password hashing provider
            _passwords = plugin.GetOrCreateSingleton<ManagedPasswordHashing>();

#pragma warning disable CA5394 // Do not use insecure randomness
            int randomDelay = Random.Shared.Next(1000, 4000);
#pragma warning restore CA5394 // Do not use insecure randomness

            //Create tables, but give plenty of delay on startup
            _ = plugin.ObserveWork(() => CreateDatabaseTables(plugin), randomDelay);
        }

        public UserManager(PluginBase plugin, IConfigScope config):this(plugin)
        {
            _randomPasswordLength = config.GetValueOrDefault(
                property: "random_password_length", 
                DefaultRandomPasswordLength
            );
        }

        /*
         * Create the databases!
         */
        private static async Task CreateDatabaseTables(PluginBase plugin)
        {
            //Ensure the database is created
            await plugin.EnsureDbCreatedAsync<UsersContext>(plugin);
        }

        ///<inheritdoc/>
        public IPasswordHashingProvider? GetHashProvider() => _passwords;

        ///<inheritdoc/>
        public string ComputeSafeUserId(string input)
        {
            return ManagedHash.ComputeHash(input, HashAlg.SHA1, HashEncodingMode.Hexadecimal);
        }

        private static string GetSafeRandomId()
        {
            return RandomHash.GetRandomHash(HashAlg.SHA1, 64, HashEncodingMode.Hexadecimal);
        }

        private static PrivateString GetRandomPassword(IPasswordHashingProvider hashProvider, int size)
        {
            ArgumentNullException.ThrowIfNull(hashProvider);

            //Get random bytes
            using UnsafeMemoryHandle<byte> randBuffer = MemoryUtil.UnsafeAlloc(size);
            try
            {
                RandomHash.GetRandomBytes(randBuffer.Span);
                
                return hashProvider.Hash(randBuffer.Span);
            }
            finally
            {
                //Zero the block and return to pool
                MemoryUtil.InitializeBlock(
                    ref randBuffer.GetReference(), 
                    randBuffer.IntLength
                );
            }
        }

        private static PrivateString GetRandomPassword(int size)
        {            
            using UnsafeMemoryHandle<byte> randBuffer = MemoryUtil.UnsafeAlloc(size);
            try
            {
                RandomHash.GetRandomBytes(randBuffer.Span);

                /*
                 * Convert to base64 url safe string, so it can be saved safely into
                 * a database with character restrictions.
                 */
                return new(
                    VnEncoding.Base64UrlEncode(randBuffer.Span, includePadding: false), 
                    ownsReferrence: true
                );
            }
            finally
            {
                //Zero the block and return to pool
                MemoryUtil.InitializeBlock(
                    ref randBuffer.GetReference(),
                    randBuffer.IntLength
                );
            }
        }

        private async Task<IUser> CreateUserInternalAsync(UserEntry user, UserStatus initStatus, CancellationToken cancellation)
        {
            await using UsersContext db = new(_dbOptions.Value);

            //See if user exists by its id or by its email
            bool exists = await (from s in db.Users
                                 where s.Id == user.Id || s.UserId == user.UserId
                                 select s)
                                 .AnyAsync(cancellation);
            if (exists)
            {
                //Rollback transaction
                await db.SaveAndCloseAsync(false, cancellation);

                throw new UserExistsException("The user already exists");
            }

            db.Users.Add(user);

            ERRNO count = await db.SaveAndCloseAsync(true, cancellation);

            if (count)
            {
                return new UserData(this, user)
                {
                    Status = initStatus
                };
            }

            throw new UserCreationFailedException($"Failed to create the new user due to a database error. result: {count}");
        }

        ///<inheritdoc/>
        public async Task<IUser> CreateUserAsync(
            IUserCreationRequest creation, 
            string? userId,
            IPasswordHashingProvider? hashProvider,
            CancellationToken cancellation = default
        )
        {
            ArgumentNullException.ThrowIfNull(creation);
            ArgumentException.ThrowIfNullOrEmpty(creation.Username, nameof(creation.Username));
           
            PStringWrapper storedPassword;

            if(creation.Password is null)
            {
                /*
                 * Password is null so we need to generate a new password and 
                 * assign it to the hash value
                 * 
                 * If the hashing provider is supplied we can compute the 
                 * hash directly and avoid some overhead
                 * 
                 * Otherwise we generate a new random password and do not
                 * hash it.
                 */

                if (hashProvider is not null)
                {
                    storedPassword = new(
                        value: GetRandomPassword(hashProvider, _randomPasswordLength),
                        ownsString: true
                    );
                }
                else
                {
                    //Dispose always happens in the finally block
#pragma warning disable CA2000 // Dispose objects before losing scope
                    storedPassword = new(
                        value: GetRandomPassword(_randomPasswordLength),
                        ownsString: true
                    );
#pragma warning restore CA2000 // Dispose objects before losing scope
                }
            }
            else
            {
                if (hashProvider is not null)
                {
                    storedPassword = new(
                        value: hashProvider.Hash(creation.Password),
                        ownsString: true
                    );
                }
                else
                {
                    //The raw password is used, and cannot be erased by our call
                    storedPassword = new(creation.Password, ownsString: false);
                }
            }

            Debug.Assert(storedPassword.Value is not null, "Stored password must be assigned");

            DateTime now = DateTime.UtcNow;

            UserEntry usr = new()
            {
                Id              = userId ?? GetSafeRandomId(),  //Create a safe user-id if not set
                UserId          = creation.Username,
                PrivilegeLevel  = (long)creation.Privileges,
                UserData        = null,
                Created         = now,
                LastModified    = now,
                PassHash        = storedPassword.GetStringReference(),    //Unwrap the raw string
            };

            try
            {
                return await CreateUserInternalAsync(usr, creation.InitialStatus, cancellation);
            }
            catch (UserExistsException)
            {
                throw;
            }
            catch (UserCreationFailedException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new UserCreationFailedException("Failed to create the user account", ex);
            }
            finally
            {
                //Always remove password ref
                usr.PassHash = null;

                storedPassword.Erase();
            }
        }

        ///<inheritdoc/>
        public Task<IUser> CreateUserAsync(IUserCreationRequest creation, string? userId, CancellationToken cancellation = default)
        {
            ArgumentNullException.ThrowIfNull(creation);

            return CreateUserAsync(
                creation,
                userId,
                //Pass null if password is not meant to be hashed
                creation.UseRawPassword ? null : GetHashProvider(),
                cancellation
            );
        }        

        ///<inheritdoc/>
        public async Task<ERRNO> ValidatePasswordAsync(
            IUser user, 
            PrivateString password, 
            IPasswordHashingProvider? hashProvider, 
            CancellationToken cancellation = default
        )
        {
            ArgumentNullException.ThrowIfNull(user);
            ArgumentNullException.ThrowIfNull(password);

            //Try to get the user's password or hash
            using PrivateString? passHash = await RecoverPasswordAsync(user, cancellation);

            if (passHash is null)
            {
                return UserPassValResult.Null;
            }

            //See if hashing is bypassed
            if (hashProvider is null)
            {
                //Compare raw passwords
                return ComparePrivateStrings(password, passHash)
                    ? UserPassValResult.Success
                    : UserPassValResult.Failed;
            }
            else
            {
                //Verify password hashes
                return hashProvider.Verify(passHash, password)
                    ? UserPassValResult.Success
                    : UserPassValResult.Failed;
            }

            static bool ComparePrivateStrings(PrivateString a, PrivateString b)
            {
                ReadOnlySpan<char> aSpan = a.ToReadOnlySpan();
                ReadOnlySpan<char> bSpan = b.ToReadOnlySpan();

                /*
                 * Do a byte-wise comparison over the passwords. This 
                 * is completely string invariant. They must be byte 
                 * identical to be considered equal.
                 */
                return CryptographicOperations.FixedTimeEquals(
                    MemoryMarshal.AsBytes(aSpan), 
                    MemoryMarshal.AsBytes(bSpan)
                );
            }
        }

        ///<inheritdoc/>
        public Task<ERRNO> ValidatePasswordAsync(IUser user, PrivateString password, PassValidateFlags flags, CancellationToken cancellation = default)
        {
            return ValidatePasswordAsync(
                user,
                password,
                //No hashing provider if the user requested a bypass
                (flags & PassValidateFlags.BypassHashing) > 0 ? null : GetHashProvider(),
                cancellation
            );
        }

        ///<inheritdoc/>
        public async Task<PrivateString?> RecoverPasswordAsync(IUser user, CancellationToken cancellation = default)
        {
            ArgumentNullException.ThrowIfNull(user);

            await using UsersContext db = new(_dbOptions.Value);           

            //Get a user entry that only contains the password hash and user-id
            UserEntry? usr = await (from s in db.Users
                                    where s.Id == user.UserID
                                    select new UserEntry
                                    {
                                        Id          = s.Id,
                                        PassHash    = s.PassHash,
                                        Version     = s.Version
                                    })
                                   .SingleOrDefaultAsync(cancellation);

            //Close transactions and return
            await db.SaveAndCloseAsync(true, cancellation);

            //Convert to private string
            return PrivateString.ToPrivateString(usr?.PassHash, true);
        }

      

        public async Task<ERRNO> UpdatePasswordAsync(
            IUser user, 
            PrivateString newPass, 
            IPasswordHashingProvider? hashProvider, 
            CancellationToken cancellation = default
        )
        {
            ArgumentNullException.ThrowIfNull(user);
            if (PrivateString.IsNullOrEmpty(newPass))
            {
                throw new ArgumentNullException(nameof(newPass));
            }


            //Get the entry back from the user data object
            UserEntry entry = user is UserData ue ? ue.Entry : throw new ArgumentException("User must be a UserData object", nameof(user));

            await using UsersContext db = new(_dbOptions.Value);

            //Track the entry again
            db.Users.Attach(entry);

            entry.LastModified = DateTime.UtcNow;

            if (hashProvider is null)
            {
                //Update password (must cast)
                entry.PassHash = (string?)newPass;
                
                int recordsModified = await db.SaveAndCloseAsync(true, cancellation);
              
                entry.PassHash = null;

                return recordsModified;
            }
            else
            {
                //Compute the new password hash
                using PrivateString passwordHash = hashProvider.Hash(newPass);

                //Update password (must cast)
                entry.PassHash = (string?)passwordHash;
              
                int recordsModified = await db.SaveAndCloseAsync(true, cancellation);
              
                entry.PassHash = null;

                return recordsModified;
            }
        }


        ///<inheritdoc/>
        public Task<ERRNO> UpdatePasswordAsync(IUser user, PrivateString newPass, CancellationToken cancellation = default)
        {
            /*
             * Added backward compatability for obsolete methods. The default 
             * condition is to use the default password hashing provider.
             */

            return UpdatePasswordAsync(
                user,
                newPass,
                GetHashProvider(),
                cancellation
            );
        }

        ///<inheritdoc/>
        public async Task<long> GetUserCountAsync(CancellationToken cancellation = default)
        {         
            await using UsersContext db = new(_dbOptions.Value);
           
            long count = await db.Users.LongCountAsync(cancellation);
           
            await db.SaveAndCloseAsync(true, cancellation);

            return count;
        }

        [Obsolete("Removed in favor of GetUserFromUsernameAsync, transition away from email address")]
        public Task<IUser?> GetUserFromEmailAsync(string emailAddress, CancellationToken cancellation = default) 
            => GetUserFromUsernameAsync(emailAddress, cancellation);

        ///<inheritdoc/>
        public async Task<IUser?> GetUserFromUsernameAsync(string username, CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrEmpty(username);
          
            await using UsersContext db = new(_dbOptions.Value);           

            //Get user without password
            UserEntry? usr = await (from s in db.Users
                                    where s.UserId == username
                                    select new UserEntry
                                    {
                                        Id              = s.Id,
                                        Created         = s.Created,
                                        UserId          = s.UserId,
                                        LastModified    = s.LastModified,
                                        PassHash        = null,
                                        PrivilegeLevel  = s.PrivilegeLevel,
                                        UserData        = s.UserData,
                                        Version         = s.Version
                                    })
                                   .SingleOrDefaultAsync(cancellationToken);

            //Close transactions and return
            await db.SaveAndCloseAsync(true, cancellationToken);

            return usr == null ? null : new UserData(this, usr);
        }

        ///<inheritdoc/>
        public async Task<IUser?> GetUserFromIDAsync(string userId, CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrEmpty(userId);
          
            await using UsersContext db = new(_dbOptions.Value);

            //Get user without a password
            UserEntry? usr = await (from s in db.Users
                                    where s.Id == userId
                                    select new UserEntry
                                    {
                                        Id              = s.Id,
                                        Created         = s.Created,
                                        UserId          = s.UserId,
                                        LastModified    = s.LastModified,
                                        PassHash        = null,
                                        PrivilegeLevel  = s.PrivilegeLevel,
                                        UserData        = s.UserData,
                                        Version         = s.Version
                                    })
                                   .SingleOrDefaultAsync(cancellationToken);


            //Close transactions and return
            await db.SaveAndCloseAsync(true, cancellationToken);
            
            return usr == null 
                ? null 
                : new UserData(this, usr);
        }

        ///<inheritdoc/>
        async Task IAsyncResourceStateHandler.UpdateAsync(AsyncUpdatableResource resource, object state, CancellationToken cancellation)
        {
            //recover user-data object
            UserEntry entry = (state as UserEntry)!;
            ERRNO result;
            try
            {                
                await using UsersContext db = new(_dbOptions.Value);              

                //Track the entry again
                db.Users.Attach(entry);

                //Set all mutable entry modified flags
                db.Entry(entry).Property(x => x.UserData).IsModified = true;
                db.Entry(entry).Property(x => x.PrivilegeLevel).IsModified = true;

                //Update modified time
                entry.LastModified = DateTime.UtcNow;

                
                result = await db.SaveAndCloseAsync(true, cancellation);
            }
            catch (Exception ex)
            {
                throw new UserUpdateException("", ex);
            }
            if (!result)
            {
                throw new UserUpdateException("The update operation failed because the transaction returned 0 updated records", null);
            }
        }

        ///<inheritdoc/>
        async Task IAsyncResourceStateHandler.DeleteAsync(AsyncUpdatableResource resource, CancellationToken cancellation)
        {
            //recover user-data object
            UserData user = (resource as UserData)!;
            ERRNO result;
            try
            {                
                await using UsersContext db = new(_dbOptions.Value);              

                //Delete the user from the database
                db.Users.Remove(user.Entry);
              
                result = await db.SaveAndCloseAsync(true, cancellation);
            }
            catch (Exception ex)
            {
                throw new UserDeleteException("Failed to delete the user entry from the database", ex);
            }
            if (!result)
            {
                throw new UserDeleteException("Failed to delete the user account because of a database failure, the user may already be deleted", null);
            }
        }

        private readonly struct PStringWrapper(PrivateString? value, bool ownsString)
        {
            public readonly PrivateString? Value = value;

            ///<inheritdoc/>
            public readonly void Erase()
            {
                //Only erase if the string is owned
                if (ownsString && Value is not null)
                {
                    Value.Erase();
                }
            }

            public string? GetStringReference() => (string?)Value;
        }
    }
}
