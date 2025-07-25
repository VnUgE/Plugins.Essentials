/*
* Copyright (c) 2025 Vaughn Nugent
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
            plugin.Log.Warn("Page router loaded but no route store was loaded. Routing functionality is disabled.");
        }

        public ManagedRouteStore(PluginBase plugin, IConfigScope config)
        {
            string? store = config.GetValueOrDefault("type", "xml");
            ILogProvider logger = plugin.Log.CreateScope("Router");

            switch (store)
            {
                case "xml":
                    logger.Information("Using XML route store.");
                    _routeStore = plugin.GetOrCreateSingleton<XmlRouteStore>();
                    break;
                default:
                    plugin.Log.Warn("Unknown route store type '{storeName}', defaulting to XML route store.", store);
                    goto case "xml";
            }
        }

        ///<inheritdoc/>
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
