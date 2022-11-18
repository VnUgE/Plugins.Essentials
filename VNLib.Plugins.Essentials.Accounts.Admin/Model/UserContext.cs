
using Microsoft.EntityFrameworkCore;

using VNLib.Plugins.Extensions.Data;

namespace VNLib.Plugins.Essentials.Accounts.Admin.Model
{
    internal class UserContext : TransactionalDbContext
    {
        public DbSet<User> Users { get; set; }
#nullable disable
        public UserContext(DbContextOptions options):base(options)
        {

        }
    }
}
