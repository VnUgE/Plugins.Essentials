﻿/*
* Copyright (c) 2022 Vaughn Nugent
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

using VNLib.Net.Http;
using VNLib.Utils.Logging;
using VNLib.Plugins.Extensions.Loading.Sql;
using VNLib.Plugins.Extensions.Loading.Events;
using VNLib.Plugins.Essentials.Content.Routing.Model;
using static VNLib.Plugins.Essentials.Accounts.AccountManager;

namespace VNLib.Plugins.Essentials.Content.Routing
{
    internal class Router : IPageRouter, IIntervalScheduleable
    {
        private static readonly RouteComparer Comparer = new();

        private readonly RouteStore Store;

        private readonly ConcurrentDictionary<IWebRoot, Task<ReadOnlyCollection<Route>>> RouteTable;

        public Router(PluginBase plugin)
        {
            Store = new(plugin.GetContextOptions());
            plugin.ScheduleInterval(this, TimeSpan.FromSeconds(30));
            RouteTable = new();
        }

        ///<inheritdoc/>
        public async ValueTask<FileProcessArgs> RouteAsync(HttpEntity entity)
        {
            ulong privilage = READ_MSK;
            //Only select privilages for logged-in users
            if (entity.Session.IsSet && entity.LoginCookieMatches() || entity.TokenMatches())
            {
                privilage = entity.Session.Privilages;
            }
            //Get the routing table for the current host
            ReadOnlyCollection<Route> routes = await RouteTable.GetOrAdd(entity.RequestedRoot, LoadRoutesAsync);
            //Find the proper routine for the connection
            return FindArgs(routes, entity.RequestedRoot.Hostname, entity.Server.Path, privilage);
        }

        /// <summary>
        /// Clears all cached routines from the database
        /// </summary>
        public void ResetRoutes() => RouteTable.Clear();

        private async Task<ReadOnlyCollection<Route>> LoadRoutesAsync(IWebRoot root)
        {
            List<Route> collection = new();
            //Load all routes 
            _ = await Store.GetPageAsync(collection, 0, int.MaxValue);
            //Select only exact match routes, or wildcard routes
            return (from r in collection
                    where r.Hostname.EndsWith(root.Hostname, StringComparison.OrdinalIgnoreCase) || r.Hostname == "*"
                    //Orderby path "specificity" longer pathts are generally more specific, so filter order
                    orderby r.MatchPath.Length ascending
                    select r)
                    .ToList()
                    .AsReadOnly();
        }


        private static FileProcessArgs FindArgs(ReadOnlyCollection<Route> routes, string hostname, string path, ulong privilages)
        {
            //Rent an array to sort routes for the current user
            Route[] matchArray = ArrayPool<Route>.Shared.Rent(routes.Count);
            int count = 0;
            //Search for routes that match
            for(int i = 0; i < routes.Count; i++)
            {
                if(Matches(routes[i], hostname, path, privilages))
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
                return FileProcessArgs.Continue;
            }
            //Get sorting span for matches
            Span<Route> found = matchArray.AsSpan(0, count);
            //Sort the found rules
            found.Sort(Comparer);
            //Select the last element
            Route selected = found[^1];
            //Return array to pool
            ArrayPool<Route>.Shared.Return(matchArray);
            return selected.MatchArgs;
        }

        /// <summary>
        /// Determines if a route can be matched to a hostname, resource path, and a 
        /// privilage level
        /// </summary>
        /// <param name="route">The route to test against</param>
        /// <param name="hostname">The hostname to test</param>
        /// <param name="path">The resource path to test</param>
        /// <param name="privilages">The privialge level to search for</param>
        /// <returns>True if the route can be matched to the resource and the privialge level</returns>
        private static bool Matches(Route route, ReadOnlySpan<char> hostname, ReadOnlySpan<char> path, ulong privilages)
        {
            //Get span of hostname to stop string heap allocations during comparisons
            ReadOnlySpan<char> routineHost = route.Hostname;
            ReadOnlySpan<char> routinePath = route.MatchPath;
            //Test if hostname hostname matches exactly (may be wildcard) or hostname begins with a wildcard and ends with the request hostname
            bool hostMatch = routineHost.SequenceEqual(hostname) || (routineHost.Length > 1 && routineHost[0] == '*' && hostname.EndsWith(routineHost[1..]));
            if (!hostMatch)
            {
                return false;
            }
            //Test if path is a wildcard, matches exactly, or if the path is a wildcard path, that the begining of the reqest path matches the routine path
            bool pathMatch = routinePath == "*" || routinePath.SequenceEqual(path) || (routinePath.Length > 1 && routinePath[^1] == '*' && path.StartsWith(routinePath[..^1]));
            if (!pathMatch)
            {
                return false;
            }
            //Test if the level and group privilages match for the current routine
            return (privilages & LEVEL_MSK) >= (route.Privilage & LEVEL_MSK) && (route.Privilage & GROUP_MSK) == (privilages & GROUP_MSK);
        }

        Task IIntervalScheduleable.OnIntervalAsync(ILogProvider log, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }
    }
}
