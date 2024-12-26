/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Oauth
* File: TokenStore.cs 
*
* TokenStore.cs is part of VNLib.Plugins.Essentials.Oauth which is part of the larger 
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
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;

using Microsoft.EntityFrameworkCore;

using VNLib.Utils;
using VNLib.Plugins.Essentials.Oauth.Applications;

namespace VNLib.Plugins.Essentials.Oauth.Tokens
{
    /// <summary>
    /// Represents a database backed <see cref="ITokenManager"/> 
    /// that allows for communicating token information to 
    /// plugins
    /// </summary>
    public sealed class TokenStore(DbContextOptions Options) : ITokenManager
    {
        /// <summary>
        /// Inserts a new token into the table for a specified application id. Also determines if 
        /// the user has reached the maximum number of allowed tokens
        /// </summary>
        /// <param name="token">The token (or session id)</param>
        /// <param name="appId">The applicaiton the token belongs to</param>
        /// <param name="refreshToken">The tokens refresh token</param>
        /// <param name="maxTokens">The maxium number of allowed tokens for a given application</param>
        /// <param name="cancellation">A token to cancel the operation</param>
        /// <returns>
        /// <see cref="ERRNO.SUCCESS"/> if the opreation succeeds (aka 0x01),
        /// <see cref="ERRNO.E_FAIL"/> if the operation fails, or the number 
        /// of active tokens if the maximum has been reached.
        /// </returns>
        public async Task<ERRNO> InsertTokenAsync(string token, string appId, string? refreshToken, int maxTokens, CancellationToken cancellation)
        {
            await using UserAppContext ctx = new (Options);

            //Check active token count
            int count = await (from t in ctx.OAuthTokens
                               where t.ApplicationId == appId
                               select t)
                               .CountAsync(cancellation);
            //Check count
            if (count >= maxTokens)
            {
                return count;
            }

            DateTime now = DateTime.UtcNow;

            //Try to add the new token
            ActiveToken newToken = new()
            {
                Id              = token,
                ApplicationId   = appId,
                RefreshToken    = refreshToken,
                Created         = now,
                LastModified    = now,
            };

            //Add token to store
            _ = ctx.Add(newToken);

            return await ctx.SaveAndCloseAsync(true, cancellation);
        }

        /// <summary>
        /// Revokes/removes a single token from the store by its ID
        /// </summary>
        /// <param name="token">The token to remove</param>
        /// <param name="cancellation"></param>
        /// <returns>A task that revolves when the token is removed from the table if it exists</returns>
        public async Task RevokeTokenAsync(string token, CancellationToken cancellation)
        {
            await using UserAppContext ctx = new (Options);
            //Get the token from the db if it exists
            ActiveToken? at = await (from t in ctx.OAuthTokens
                                     where t.Id == token
                                     select t)
                                    .FirstOrDefaultAsync(cancellation);
            if (at is null)
            {
                return;
            }

            _ = ctx.OAuthTokens.Remove(at);

            _ = await ctx.SaveAndCloseAsync(commit: true, cancellation);
        }

        /// <summary>
        /// Removes all token entires that were created before the specified time
        /// </summary>
        /// <param name="validAfter">The time before which all tokens are invaid</param>
        /// <param name="cancellation">A token the cancel the operation</param>
        /// <returns>A task that resolves to a collection of tokens that were removed</returns>
        public async Task<IReadOnlyCollection<ActiveToken>> CleanupExpiredTokensAsync(DateTime validAfter, CancellationToken cancellation)
        {
            await using UserAppContext ctx = new (Options);

            //get all tokens after the specified time
            ActiveToken[] at = await (from t in ctx.OAuthTokens
                                      where t.Created < validAfter
                                      select t)
                                     .ToArrayAsync(cancellation);


            ctx.OAuthTokens.RemoveRange(at);

            _ = await ctx.SaveAndCloseAsync(commit: true, cancellation);
            return at;
        }

        ///<inheritdoc/>
        public async Task RevokeTokensAsync(IReadOnlyCollection<string> tokens, CancellationToken cancellation = default)
        {
            await using UserAppContext ctx = new (Options);
            //Get all tokenes that are contained in the collection
            ActiveToken[] at = await (from t in ctx.OAuthTokens
                                      where tokens.Contains(t.Id)
                                      select t)
                                      .ToArrayAsync(cancellation);


            ctx.OAuthTokens.RemoveRange(at);

            _ = await ctx.SaveAndCloseAsync(commit: true, cancellation);
        }

        ///<inheritdoc/>
        async Task ITokenManager.RevokeTokensForAppAsync(string appId, CancellationToken cancellation)
        {
            await using UserAppContext ctx = new (Options);
            //Get the token from the db if it exists
            ActiveToken[] at = await (from t in ctx.OAuthTokens
                                      where t.ApplicationId == appId
                                      select t)
                                    .ToArrayAsync(cancellation);

            //Set created time to 0 to invalidate the token
            foreach (ActiveToken t in at)
            {
                //Expire token so next cleanup round will wipe tokens
                t.Created = DateTime.MinValue;
            }

            _ = await ctx.SaveAndCloseAsync(commit: true, cancellation);
        }
    }
}
