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
            await using RevocationContext context = new (Options);
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
            await using RevocationContext context = new (Options);
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

            await using RevocationContext context = new (Options);
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