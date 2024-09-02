/*
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
using System.Threading.Tasks;

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

        private readonly IAsyncLazy<DbContextOptions> _dbOptions;
        private readonly IPasswordHashingProvider _passwords;

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
        { }

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

        ///<inheritdoc/>
        public async Task<IUser> CreateUserAsync(IUserCreationRequest creation, string? userId, CancellationToken cancellation = default)
        {
            ArgumentNullException.ThrowIfNull(creation);

            //Set random user-id if not set
            userId ??= GetSafeRandomId();
            ArgumentException.ThrowIfNullOrWhiteSpace(creation.Username, nameof(creation.Username));

            PrivateString? hash = null;
            
            /*
             * If a raw password is not required, it may be optionally left 
             * null for a random password to be generated. Otherwise the 
             * supplied password is hashed and stored.
             */
            if(!creation.UseRawPassword)
            {                
                hash = creation.Password == null ? 
                    _passwords.GetRandomPassword() 
                    : _passwords.Hash(creation.Password);
            }

            try
            {
                //Init db
                await using UsersContext db = new(_dbOptions.Value);

                //See if user exists by its id or by its email
                bool exists = await (from s in db.Users
                                     where s.Id == userId || s.UserId == creation.Username
                                     select s)
                                     .AnyAsync(cancellation);
                if (exists)
                {
                    //Rollback transaction
                    await db.SaveAndCloseAsync(false, cancellation);
                  
                    throw new UserExistsException("The user already exists");
                }

                DateTime now = DateTime.UtcNow;

                //Create user entry
                UserEntry usr = new()
                {
                    Id              = userId,
                    UserId          = creation.Username,
                    PrivilegeLevel  = (long)creation.Privileges,
                    UserData        = null,
                    Created         = now,
                    LastModified    = now,

                    //Cast private string for storage
                    PassHash = (string?)(creation.UseRawPassword ? creation.Password : hash),
                };

                //Add to user table
                db.Users.Add(usr);

                //Save changes
                ERRNO count = await db.SaveAndCloseAsync(true, cancellation);

                //Remove ref to password hash
                usr.PassHash = null;

                if (count)
                {
                    return new UserData(this, usr)
                    {
                        Status = creation.InitialStatus
                    };
                }

                throw new UserCreationFailedException($"Failed to create the new user due to a database error. result: {count}");
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
                hash?.Erase();
            }
        }

        ///<inheritdoc/>
        public async Task<ERRNO> ValidatePasswordAsync(IUser user, PrivateString password, PassValidateFlags flags, CancellationToken cancellation = default)
        {
            ArgumentNullException.ThrowIfNull(user);
            ArgumentNullException.ThrowIfNull(password);           

            //Try to get the user's password or hash
            using PrivateString? passHash = await RecoverPasswordAsync(user, cancellation);

            if(passHash is null)
            {
                return UserPassValResult.Null;
            }

            //See if hashing is bypassed
            if ((flags & PassValidateFlags.BypassHashing) > 0)
            {
                //Compare raw passwords
                return password.Equals(passHash) 
                    ? UserPassValResult.Success 
                    : UserPassValResult.Failed;
            }
            else
            {
                //Verify password hashes (usually defauly)
                return _passwords.Verify(passHash, password) 
                    ? UserPassValResult.Success 
                    : UserPassValResult.Failed;
            }
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

        ///<inheritdoc/>
        public async Task<ERRNO> UpdatePasswordAsync(IUser user, PrivateString newPass, CancellationToken cancellation = default)
        {
            ArgumentNullException.ThrowIfNull(newPass);
            ArgumentException.ThrowIfNullOrEmpty((string?)newPass);

            //Get the entry back from the user data object
            UserEntry entry = user is UserData ue ? ue.Entry : throw new ArgumentException("User must be a UserData object", nameof(user));
           
            await using UsersContext db = new(_dbOptions.Value);

            //Track the entry again
            db.Users.Attach(entry);

            //Compute the new password hash
            using PrivateString passwordHash = _passwords.Hash(newPass);

            //Update password (must cast)
            entry.PassHash = (string?)passwordHash;

            //Update modified time
            entry.LastModified = DateTime.UtcNow;

            //Save changes async
            int count = await db.SaveAndCloseAsync(true, cancellation);

            //Clear the new password hash
            entry.PassHash = null;
            
            return count;
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

    }
}
