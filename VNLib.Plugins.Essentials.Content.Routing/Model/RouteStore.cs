using System;
using System.Linq;

using Microsoft.EntityFrameworkCore;

using VNLib.Plugins.Extensions.Data;

namespace VNLib.Plugins.Essentials.Content.Routing.Model
{
    internal class RouteStore : DbStore<Route>
    {
        private readonly DbContextOptions Options;

        public RouteStore(DbContextOptions options)
        {
            Options = options;
        }

        public override string RecordIdBuilder => Guid.NewGuid().ToString("N");

        protected override IQueryable<Route> GetCollectionQueryBuilder(TransactionalDbContext context, params string[] constraints)
        {
            string hostname = constraints[0];
            return from route in context.Set<Route>()
                   where route.Hostname == hostname
                   select route;
        }

        protected override IQueryable<Route> GetSingleQueryBuilder(TransactionalDbContext context, params string[] constraints)
        {
            string id = constraints[0];
            return from route in context.Set<Route>()
                   where route.Id == id
                   select route;
        }

        public override TransactionalDbContext NewContext() => new RoutingContext(Options);

        protected override void OnRecordUpdate(Route newRecord, Route currentRecord)
        {
            throw new NotImplementedException();
        }
    }
}
