/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Content.Routing
* File: Router.cs 
*
* Router.cs is part of VNLib.Plugins.Essentials.Content.Routing which is part of the larger 
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
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Collections.ObjectModel;

using VNLib.Utils.Logging;
using VNLib.Utils.Extensions;
using VNLib.Plugins.Essentials.Accounts;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Essentials.Content.Routing.Model;


namespace VNLib.Plugins.Essentials.Content.Routing
{

    internal sealed class Router(PluginBase plugin) : IPageRouter
    {
        private static readonly RouteComparer Comparer = new();

        private readonly ManagedRouteStore Store = plugin.GetOrCreateSingleton<ManagedRouteStore>();
        private readonly ILogProvider Logger = plugin.Log;

        private readonly ConcurrentDictionary<IWebProcessor, Task<ReadOnlyCollection<Route>>> RouteTable = new();

        public Router(PluginBase plugin, IConfigScope config):this(plugin)
        { }

        ///<inheritdoc/>
        public async ValueTask<FileProcessArgs> RouteAsync(HttpEntity entity)
        {
            //Default to read-only privilages
            ulong privileges = AccountUtil.READ_MSK;

            //Only select privilages for logged-in users, this is a medium security check since we may not have all data available
            if (entity.Session.IsSet && entity.IsClientAuthorized(AuthorzationCheckLevel.Medium))
            {
                privileges = entity.Session.Privilages;
            }

            //Get the routing table for the current host
            ReadOnlyCollection<Route> routes = await RouteTable.GetOrAdd(entity.RequestedRoot, LoadRoutesAsync);

            //Find the proper routine for the connection
            Route? selected = SelectBestRoute(routes, entity.RequestedRoot.Hostname, entity.Server.Path, privileges);

            //Get the arguments for the selected route, if not found allow the connection to continue
            return selected?.GetArgs(entity) ?? FileProcessArgs.Continue;
        }

        /// <summary>
        /// Clears all cached routines from the database
        /// </summary>
        public void ResetRoutes() => RouteTable.Clear();


        private async Task<ReadOnlyCollection<Route>> LoadRoutesAsync(IWebProcessor root)
        {
            List<Route> collection = new();

            //Load all routes from the backing store and filter them
            await Store.GetAllRoutesAsync(collection, CancellationToken.None);

            Logger.Debug("Found {r} routes in store", collection.Count);

            //Select only exact match routes, or wildcard routes
            return (from r in collection
                    where r.Hostname.EndsWith(root.Hostname, StringComparison.OrdinalIgnoreCase) || r.Hostname == "*"
                    //Orderby path "specificity" longer pathts are generally more specific, so filter order
                    orderby r.MatchPath.Length ascending
                    select r)
                    .ToList()
                    .AsReadOnly();
        }

        /// <summary>
        /// Selects the best route for a given hostname, path, and privilage level and returns it
        /// if one could be found
        /// </summary>
        /// <param name="routes">The routes collection to read</param>
        /// <param name="hostname">The connection hostname to filter routes for</param>
        /// <param name="path">The connection url path to filter routes for</param>
        /// <param name="privileges">The calculated privialges of the connection</param>
        /// <returns>The best route match for the connection if one is found, null otherwise</returns>
        private static Route? SelectBestRoute(ReadOnlyCollection<Route> routes, string hostname, string path, ulong privileges)
        {
            //Rent an array to sort routes for the current user
            Route[] matchArray = ArrayPool<Route>.Shared.Rent(routes.Count);
            int count = 0;

            //Search for routes that match
            for (int i = 0; i < routes.Count; i++)
            {
                if (FastMatch(routes[i], hostname, path, privileges))
                {
                    //Add to sort array
                    matchArray[count++] = routes[i];
                }
            }

            //If no matches are found, return continue routine
            if (count == 0)
            {
                //Return the array to the pool
                ArrayPool<Route>.Shared.Return(matchArray);
                return null;
            }

            //If only one match is found, return it
            if (count == 1)
            {
                //Return the array to the pool
                ArrayPool<Route>.Shared.Return(matchArray);
                return matchArray[0];
            }
            else
            {
                //Get sorting span for matches
                Span<Route> found = matchArray.AsSpan(0, count);

                /*
                 * Sortining elements using the static comparer, to find the best match 
                 * out of all matching routes.
                 * 
                 * The comparer will put the most specific routes at the end of the array
                 */
                found.Sort(Comparer);

                //Select the last element
                Route selected = found[^1];

                //Return array to pool
                ArrayPool<Route>.Shared.Return(matchArray);

                return selected;
            }
        }

        /// <summary>
        /// Determines if a route can be matched to a hostname, resource path, and a 
        /// privilage level
        /// </summary>
        /// <param name="route">The route to test against</param>
        /// <param name="hostname">The hostname to test</param>
        /// <param name="path">The resource path to test</param>
        /// <param name="privileges">The privialge level to search for</param>
        /// <returns>True if the route can be matched to the resource and the privialge level</returns>
        private static bool FastMatch(Route route, ReadOnlySpan<char> hostname, ReadOnlySpan<char> path, ulong privileges)
        {
            //Get span of hostname to stop string heap allocations during comparisons
            ReadOnlySpan<char> routineHost = route.Hostname;
            ReadOnlySpan<char> routinePath = route.MatchPath;

            //Test if hostname matches
            bool hostMatch = 
                //Wildcard routine only, matches all hostnames
                (routineHost.Length == 1 && routineHost[0] == '*') 
                //Exact hostname match
                || routineHost.SequenceEqual(hostname) 
                //wildcard hostname match with trailing 
                || (routineHost.Length > 1 && routineHost[0] == '*' && hostname.EndsWith(routineHost[1..], StringComparison.OrdinalIgnoreCase));

            if (!hostMatch)
            {
                return false;
            }

            //Test if path is a wildcard, matches exactly, or if the path is a wildcard path, that the begining of the request path matches the routine path
            bool pathMatch = routinePath == "*" 
                || routinePath.Equals(path, StringComparison.OrdinalIgnoreCase)
                || (routinePath.Length > 1 && routinePath[^1] == '*' && path.StartsWith(routinePath[..^1], StringComparison.OrdinalIgnoreCase));

            if (!pathMatch)
            {
                return false;
            }

            //Test if the level and group privilages match for the current routine
            return (privileges & AccountUtil.LEVEL_MSK) >= (route.Privilege & AccountUtil.LEVEL_MSK) && (route.Privilege & AccountUtil.GROUP_MSK) == (privileges & AccountUtil.GROUP_MSK);
        }
    }
}
