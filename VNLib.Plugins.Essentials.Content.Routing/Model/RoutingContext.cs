using System;

using Microsoft.EntityFrameworkCore;

using VNLib.Plugins.Extensions.Data;

namespace VNLib.Plugins.Essentials.Content.Routing.Model
{
    internal class RoutingContext : TransactionalDbContext
    {
        public DbSet<Route> Routes { get; set; }

        public RoutingContext(DbContextOptions options) :base(options)
        {
        }
    }
}
