/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Content.Routing
* File: ManagedRouteStore.cs 
*
* ManagedRouteStore.cs is part of VNLib.Plugins.Essentials.Content.Routing which is part of the larger 
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

using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;

using VNLib.Utils.Logging;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Sql;
using VNLib.Plugins.Essentials.Content.Routing.Model;
using VNLib.Plugins.Essentials.Content.Routing.stores;

namespace VNLib.Plugins.Essentials.Content.Routing
{
    [ConfigurationName("store", Required = false)]
    internal sealed class ManagedRouteStore : IRouteStore
    {
        private readonly IRouteStore _routeStore = new DummyRouteStore();

        //empty constructor for 
        public ManagedRouteStore(PluginBase plugin) 
        {
            plugin.Log.Warn("Page router loaded but no route store was loaded. Routing funtionality is disabled.");
        }

        public ManagedRouteStore(PluginBase plugin, IConfigScope config)
        {
            //Load managed store, see if we're using the xml file or the database
            if(config.ContainsKey("route_file"))
            {
                //Load xml route store
                _routeStore = plugin.GetOrCreateSingleton<XmlRouteStore>();
            }
            else
            {
                //Load the database backed store
                _routeStore = plugin.GetOrCreateSingleton<DbRouteStore>();

                //Ensure the database is created
                _ = plugin.ObserveWork(() => plugin.EnsureDbCreatedAsync<RoutingContext>(plugin), 1000);
            }
        }

        public Task GetAllRoutesAsync(ICollection<Route> routes, CancellationToken cancellation)
        {
            return _routeStore.GetAllRoutesAsync(routes, cancellation);
        }

        private sealed class DummyRouteStore : IRouteStore
        {
            public Task GetAllRoutesAsync(ICollection<Route> routes, CancellationToken cancellation) 
                => Task.CompletedTask;
        }
    }
}
