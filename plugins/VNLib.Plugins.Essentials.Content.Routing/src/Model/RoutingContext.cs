/*
* Copyright (c) 2022 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Content.Routing
* File: RoutingContext.cs 
*
* RoutingContext.cs is part of VNLib.Plugins.Essentials.Content.Routing which is part of the larger 
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
