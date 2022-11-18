using Microsoft.EntityFrameworkCore;

using VNLib.Plugins.Extensions.Data;

namespace VNLib.Plugins.Essentials.Accounts.Registration.TokenRevocation
{
    internal class RevocationContext : TransactionalDbContext
    {
        public DbSet<RevokedToken> RevokedRegistrationTokens { get; set; }
        
        public RevocationContext(DbContextOptions options) : base(options)
        {}
    }
}