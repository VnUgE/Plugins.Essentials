/*
* Copyright (c) 2022 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Content.Routing
* File: RouteStore.cs 
*
* RouteStore.cs is part of VNLib.Plugins.Essentials.Content.Routing which is part of the larger 
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
