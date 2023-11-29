/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Content.Routing
* File: DbRouteStore.cs 
*
* DbRouteStore.cs is part of VNLib.Plugins.Essentials.Content.Routing which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Content.Routing is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Content.Routing is distributed in the hope that it will be useful,
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
using System.Collections.Generic;
using System.Threading.Tasks;

using Microsoft.EntityFrameworkCore;

using VNLib.Plugins.Extensions.Data;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Sql;
using VNLib.Plugins.Extensions.Data.Abstractions;
using VNLib.Plugins.Extensions.Data.Extensions;

namespace VNLib.Plugins.Essentials.Content.Routing.Model
{
    internal sealed class DbRouteStore : DbStore<Route>, IRouteStore
    {
        private readonly IAsyncLazy<DbContextOptions> Options;

        public override IDbQueryLookup<Route> QueryTable { get; } = new DbQueries();

        public DbRouteStore(PluginBase plugin)
        {
            //Load the db context options
            Options = plugin.GetContextOptionsAsync();
        }

        ///<inheritdoc/>
        public Task GetAllRoutesAsync(ICollection<Route> routes, CancellationToken cancellation)
        {
            //Get all routes as a single page from the database
            return this.GetPageAsync(routes, 0, int.MaxValue, cancellation);
        }

        ///<inheritdoc/>
        public override string GetNewRecordId() => Guid.NewGuid().ToString("N");

        ///<inheritdoc/>
        public override IDbContextHandle GetNewContext() => new RoutingContext(Options.Value);

        ///<inheritdoc/>
        public override void OnRecordUpdate(Route newRecord, Route currentRecord)
        {
            throw new NotSupportedException();
        }

        private sealed record class DbQueries : IDbQueryLookup<Route>
        {
            public IQueryable<Route> GetCollectionQueryBuilder(IDbContextHandle context, params string[] constraints)
            {
                string hostname = constraints[0];
                return from route in context.Set<Route>()
                       where route.Hostname == hostname
                       select route;
            }

            public IQueryable<Route> GetSingleQueryBuilder(IDbContextHandle context, params string[] constraints)
            {

                string id = constraints[0];
                return from route in context.Set<Route>()
                       where route.Id == id
                       select route;
            }
        }
    }
}
