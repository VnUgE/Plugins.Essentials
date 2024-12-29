/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Oauth
* File: ApplicationStore.cs 
*
* ApplicationStore.cs is part of VNLib.Plugins.Essentials.Oauth which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Oauth is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Oauth is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

using System;
using System.Data;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.EntityFrameworkCore;

using VNLib.Hashing;
using VNLib.Utils;
using VNLib.Utils.Memory;
using VNLib.Plugins.Extensions.Data;
using VNLib.Plugins.Essentials.Accounts;
using VNLib.Plugins.Essentials.Oauth.Tokens;
using VNLib.Plugins.Extensions.Data.Abstractions;
using VNLib.Plugins.Extensions.Data.Extensions;

namespace VNLib.Plugins.Essentials.Oauth.Applications
{
    /// <summary>
    /// A DbStore for <see cref="UserApplication"/>s for OAuth2 client applications
    /// </summary>
    /// <remarks>
    /// Initializes a new <see cref="ApplicationStore"/> data store
    /// uisng the specified EFCore <see cref="DbContextOptions"/> object.
    /// </remarks>
    /// <param name="conextOptions">EFCore context options for connecting to a remote data-store</param>
    /// <param name="secretHashing">A <see cref="PasswordHashing"/> structure for hashing client secrets</param>
    public sealed partial class ApplicationStore(DbContextOptions conextOptions, IPasswordHashingProvider secretHashing) : DbStore<UserApplication>
    {
        public const int SECRET_SIZE = 32;
        public const int CLIENT_ID_SIZE = 16;

        private readonly IPasswordHashingProvider SecretHashing = secretHashing;
        private readonly DbContextOptions ConextOptions = conextOptions;
        private readonly ITokenManager TokenStore = new TokenStore(conextOptions);


        /// <summary>
        /// Generates a client application secret using the <see cref="RandomHash"/> library
        /// </summary>
        /// <returns>The RNG secret</returns>
        public static PrivateString GenerateSecret(int secretSize = SECRET_SIZE)
        {
            string secret = RandomHash.GetRandomHex(secretSize).ToLower(null)!;
            return PrivateString.ToPrivateString(secret, true);
        }

        /// <inheritdoc/>
        public override IDbContextHandle GetNewContext() => new UserAppContext(ConextOptions);

        /// <inheritdoc/>
        public override string GetNewRecordId() => RandomHash.GetRandomHex(CLIENT_ID_SIZE).ToLower(null);

        ///<inheritdoc/>
        public override void OnRecordUpdate(UserApplication newRecord, UserApplication currentRecord)
        {
            currentRecord.AppDescription = newRecord.AppDescription;
            currentRecord.AppName = newRecord.AppName;
        }

        /// <summary>
        /// Updates the secret of an application, and if successful returns the new raw secret data
        /// </summary>
        /// <param name="userId">The user-id of that owns the application</param>
        /// <param name="appId">The id of the application to update</param>
        /// <returns>A task that resolves to the raw secret that was used to generate the hash, or null if the operation failed</returns>
        public async Task<PrivateString?> UpdateSecretAsync(string userId, string appId, CancellationToken cancellation)
        {
            /*
             * Delete open apps first, incase there are any issues, worse case
             * the user's will have to re-authenticate.
             * 
             * If we delete tokens after update, the user wont see the new 
             * secret and may lose access to the updated app, not a big deal
             * but avoidable.
             */
            await TokenStore.RevokeTokensForAppAsync(appId, cancellation);

            //Generate the new secret
            PrivateString secret = GenerateSecret();
            //Hash the secret
            using PrivateString secretHash = SecretHashing.Hash(secret);
            //Open new db context
            await using UserAppContext Database = new(ConextOptions);

            //Get the app to update the secret on 
            UserApplication? app = await (from ap in Database.OAuthApps
                                         where ap.UserId == userId && ap.Id == appId
                                         select ap)
                                         .SingleOrDefaultAsync(cancellation);
            if (app is null)
            {
                return null;
            }

            //Store the new secret hash
            app.SecretHash = (string)secretHash;

            //Save changes
            if (await Database.SaveAndCloseAsync(true, cancellation) <= 0)
            {
                return null;
            }

            //return the raw secret
            return secret;
        }

        /// <summary>
        /// Attempts to retreive an application by the specified client id and compares the raw secret against the 
        /// stored secret hash.
        /// </summary>
        /// <param name="clientId">The clientid of the application to search</param>
        /// <param name="secret">The secret to compare against</param>
        /// <returns>True if the application was found and the secret matches the stored secret, false if the appliation was not found or the secret does not match</returns>
        public async Task<UserApplication?> VerifyAppAsync(string clientId, PrivateString secret, CancellationToken cancellation)
        {
            UserApplication? app;

            //Open new db context
            await using (UserAppContext Database = new(ConextOptions))
            {
                //Get the application with its secret
                app = await (from userApp in Database.OAuthApps
                             where userApp.ClientId == clientId
                             select userApp)
                             .FirstOrDefaultAsync(cancellation);

                //commit the transaction
                await Database.SaveAndCloseAsync(true, cancellation);
            }

            //make sure app exists
            if (string.IsNullOrWhiteSpace(app?.UserId) || !app.ClientId!.Equals(clientId, StringComparison.Ordinal))
            {
                //Not found or not valid
                return null;
            }

            //Convert the secret hash to a private string so it will be cleaned up
            using PrivateString secretHash = (PrivateString)app.SecretHash!;

            //Verify the secret against the hash
            if (SecretHashing.Verify(secretHash, secret))
            {
                app.SecretHash = null;
                //App was successfully verified
                return app;
            }

            //Not found or not valid
            return null;
        }

        /// <summary>
        /// Creates and initializes a new <see cref="UserApplication"/> with a random clientid and 
        /// secret that must be disposed
        /// </summary>
        /// <param name="record">The new record to create</param>
        /// <param name="cancellation"></param>
        /// <returns>The result of the operation</returns>
        public async Task<ERRNO> CreateAppAsync(UserApplication record, CancellationToken cancellation = default)
        {
            record.RawSecret = GenerateSecret();
            //Hash the secret
            using PrivateString secretHash = SecretHashing.Hash(record.RawSecret);
            record.ClientId = GetNewRecordId();
            record.SecretHash = (string)secretHash;
            //Wait for the record to be created before wiping the secret
            return await this.CreateAsync(record, cancellation);
        }

        public override IDbQueryLookup<UserApplication> QueryTable { get; } = new ApplicationQueries();

        private sealed class ApplicationQueries : IDbQueryLookup<UserApplication>
        {
            ///<inheritdoc/>
            public IQueryable<UserApplication> GetCollectionQueryBuilder(IDbContextHandle context, params string[] constraints)
            {
                //When only a single contraint is specified, we are getting all applications for a user
                if (constraints.Length == 1)
                {
                    string userId = constraints[0];

                    UserAppContext ctx = (context as UserAppContext)!;
                    //Get the user's applications based on their userid
                    return from userApp in ctx.OAuthApps
                           where userApp.UserId == userId
                           orderby userApp.Created ascending
                           select new UserApplication
                           {
                               AppDescription = userApp.AppDescription,
                               Id = userApp.Id,
                               AppName = userApp.AppName,
                               ClientId = userApp.ClientId,
                               Created = userApp.Created,
                               Permissions = userApp.Permissions
                           };
                }
                //When two constraints are specified, we are getting a single application
                else
                {
                    string appId = constraints[0];
                    string userId = constraints[1];

                    UserAppContext ctx = (context as UserAppContext)!;
                    //Query to get a new single application with limit results output
                    return from userApp in ctx.OAuthApps
                           where userApp.UserId == userId
                           && userApp.Id == appId
                           select new UserApplication
                           {
                               AppDescription = userApp.AppDescription,
                               Id = userApp.Id,
                               AppName = userApp.AppName,
                               ClientId = userApp.ClientId,
                               Created = userApp.Created,
                               Permissions = userApp.Permissions,
                               Version = userApp.Version
                           };
                }
            }

            ///<inheritdoc/>
            public IQueryable<UserApplication> GetSingleQueryBuilder(IDbContextHandle context, params string[] constraints)
            {
                string appId = constraints[0];
                string userId = constraints[1];
                UserAppContext ctx = (context as UserAppContext)!;
                //Query to get a new single application with limit results output
                return from userApp in ctx.OAuthApps
                       where userApp.UserId == userId
                       && userApp.Id == appId
                       select new UserApplication
                       {
                           AppDescription = userApp.AppDescription,
                           Id = userApp.Id,
                           AppName = userApp.AppName,
                           ClientId = userApp.ClientId,
                           Created = userApp.Created,
                           Permissions = userApp.Permissions,
                           Version = userApp.Version
                       };
            }

            ///<inheritdoc/>
            public IQueryable<UserApplication> AddOrUpdateQueryBuilder(IDbContextHandle context, UserApplication record)
            {
                UserAppContext ctx = (context as UserAppContext)!;
                //get a single record by the id for the specific user
                return from userApp in ctx.OAuthApps
                       where userApp.UserId == record.UserId
                       && userApp.Id == record.Id
                       select userApp;
            }

        }
    }
}