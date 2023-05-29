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
using System.Collections.Generic;
using System.Threading.Tasks;

using Microsoft.EntityFrameworkCore;

using VNLib.Plugins.Extensions.Data;
using VNLib.Plugins.Extensions.Loading.Sql;

namespace VNLib.Plugins.Essentials.Content.Routing.Model
{
    internal class DbRouteStore : DbStore<Route>, IRouteStore
    {
        private readonly DbContextOptions Options;

        public DbRouteStore(PluginBase plugin)
        {
            //Load the db context options
            Options = plugin.GetContextOptions();
        }

        ///<inheritdoc/>
        public Task GetAllRoutesAsync(ICollection<Route> routes)
        {
            //Get all routes as a single page from the database
            return GetPageAsync(routes, 0, int.MaxValue);
        }

        ///<inheritdoc/>
        public override string RecordIdBuilder => Guid.NewGuid().ToString("N");

        ///<inheritdoc/>
        protected override IQueryable<Route> GetCollectionQueryBuilder(TransactionalDbContext context, params string[] constraints)
        {
            string hostname = constraints[0];
            return from route in context.Set<Route>()
                   where route.Hostname == hostname
                   select route;
        }

        ///<inheritdoc/>
        protected override IQueryable<Route> GetSingleQueryBuilder(TransactionalDbContext context, params string[] constraints)
        {
            string id = constraints[0];
            return from route in context.Set<Route>()
                   where route.Id == id
                   select route;
        }

        ///<inheritdoc/>
        public override TransactionalDbContext NewContext() => new RoutingContext(Options);

        ///<inheritdoc/>
        protected override void OnRecordUpdate(Route newRecord, Route currentRecord)
        {
            throw new NotSupportedException();
        }

    }
}
