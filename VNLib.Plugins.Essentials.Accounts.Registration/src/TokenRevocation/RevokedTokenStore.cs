/*
* Copyright (c) 2022 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts.Registration
* File: RevokedTokenStore.cs 
*
* RevokedTokenStore.cs is part of VNLib.Plugins.Essentials.Accounts.Registration which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Accounts.Registration is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Accounts.Registration is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

using System.Collections;

using Microsoft.EntityFrameworkCore;

using VNLib.Utils;

namespace VNLib.Plugins.Essentials.Accounts.Registration.TokenRevocation
{
    internal class RevokedTokenStore
    {
        private readonly DbContextOptions Options;

        public RevokedTokenStore(DbContextOptions options)
        {
            Options = options;
        }

        public async Task<bool> IsRevokedAsync(string token, CancellationToken cancellation)
        {
            await using RegistrationContext context = new (Options);
            await context.OpenTransactionAsync(cancellation);

            //Select any that match tokens
            bool any = await (from t in context.RevokedRegistrationTokens
                              where t.Token == token
                              select t).AnyAsync(cancellation);

            await context.CommitTransactionAsync(cancellation);
            return any;
        }

        public async Task RevokeAsync(string token, CancellationToken cancellation)
        {
            await using RegistrationContext context = new (Options);
            await context.OpenTransactionAsync(cancellation);

            //Add to table
            context.RevokedRegistrationTokens.Add(new RevokedToken()
            {
                Created = DateTime.UtcNow,
                Token = token
            });

            //Save changes and commit transaction
            await context.SaveChangesAsync(cancellation);
            await context.CommitTransactionAsync(cancellation);
        }

        /// <summary>
        /// Removes expired records from the store
        /// </summary>
        /// <param name="validFor">The time a token is valid for</param>
        /// <param name="cancellation">A token that cancels the async operation</param>
        /// <returns>The number of records evicted from the store</returns>
        public async Task<ERRNO> CleanTableAsync(TimeSpan validFor, CancellationToken cancellation)
        {
            DateTime expiredBefore = DateTime.UtcNow.Subtract(validFor);

            await using RegistrationContext context = new (Options);
            await context.OpenTransactionAsync(cancellation);

            //Select any that match tokens
            RevokedToken[] expired = await context.RevokedRegistrationTokens.Where(t => t.Created < expiredBefore)
                .Select(static t => t)
                .ToArrayAsync(cancellation);


            context.RevokedRegistrationTokens.RemoveRange(expired);

            ERRNO count =await context.SaveChangesAsync(cancellation);
            
            await context.CommitTransactionAsync(cancellation);

            return count;
        }
    }
}