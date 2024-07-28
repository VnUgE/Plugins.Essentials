/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Content.Routing
* File: XmlRouteStore.cs 
*
* XmlRouteStore.cs is part of VNLib.Plugins.Essentials.Content.Routing which is part of the larger 
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
using System.IO;
using System.Xml;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;

using VNLib.Utils.IO;
using VNLib.Utils.Memory;
using VNLib.Utils.Logging;
using VNLib.Utils.Extensions;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Essentials.Content.Routing.Model;

namespace VNLib.Plugins.Essentials.Content.Routing.stores
{
    [ConfigurationName("store")]
    internal sealed class XmlRouteStore : IRouteStore
    {
        private readonly string _routeFile;

        public XmlRouteStore(PluginBase plugin, IConfigScope config)
        {
            //Get the route file path
            _routeFile = config.GetRequiredProperty<string>("route_file");

            //Make sure the file exists
            if (!FileOperations.FileExists(_routeFile))
            {
                throw new FileNotFoundException("Missing required route xml file", _routeFile);
            }

            plugin.Log.Debug("Loading routes from {0}", _routeFile);
        }

        ///<inheritdoc/>
        public async Task GetAllRoutesAsync(ICollection<Route> routes, CancellationToken cancellation)
        {
            using VnMemoryStream memStream = new();

            //Load the route file
            await using (FileStream routeFile = new(_routeFile, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                //Read the route file into memory
                await routeFile.CopyToAsync(memStream, 8192, MemoryUtil.Shared, cancellation);
            }

            //Rewind the memory stream
            memStream.Seek(0, SeekOrigin.Begin);

            //Parse elements into routes
            ParseElements(memStream, routes);
        }

        private static void ParseElements(VnMemoryStream ms, ICollection<Route> routes)
        {
            //Read contents into xml doc for reading
            XmlDocument xmlDoc = new();
            xmlDoc.Load(ms);

            //Get route elements
            XmlNodeList? routeElements = xmlDoc.SelectNodes("routes/route");

            //If no route elements, exit
            if (routeElements == null)
            {
                return;
            }

            foreach (XmlNode routeEl in routeElements)
            {
                Route route = new();

                //See if route is disabled
                string? disabledAtr = routeEl.Attributes["disabled"]?.Value;
                //If disabled, skip route
                if (disabledAtr != null)
                {
                    continue;
                }

                //Get the route routine value
                string? routineAtr = routeEl.Attributes["routine"]?.Value;
                _ = routineAtr ?? throw new XmlException("Missing required attribute 'routine' in route element");

                //Try to get the routime enum value
                if (uint.TryParse(routineAtr, out uint r))
                {
                    route.Routine = (FpRoutine)r;
                }
                else
                {
                    throw new XmlException("The value of the 'routine' attribute is not a valid FpRoutine enum value");
                }

                //read priv level attribute
                string? privAtr = routeEl.Attributes["privilege"]?.Value;
                _ = privAtr ?? throw new XmlException("Missing required attribute 'privilege' in route element");

                //Try to get the priv level enum value
                if (ulong.TryParse(privAtr, out ulong priv))
                {
                    route.Privilege = priv;
                }
                else
                {
                    throw new XmlException("The value of the 'priv' attribute is not a valid unsigned 64-bit integer");
                }

                //Get hostname element value
                string? hostEl = routeEl["hostname"]?.InnerText;
                route.Hostname = hostEl ?? throw new XmlException("Missing required element 'hostname' in route element");

                //Get the path element value
                string? pathEl = routeEl["path"]?.InnerText;
                route.MatchPath = pathEl ?? throw new XmlException("Missing required element 'path' in route element");

                //Get the optional alternate path element value
                route.Alternate = routeEl["alternate"]?.InnerText;

                //Check for rewrite routine, if rewrite, get rewrite and replace elements
                if (route.Routine == Route.RewriteRoutine)
                {
                    //Get the rewrite element value
                    string? rewriteEl = routeEl["rewrite"]?.InnerText;
                    route.RewriteSearch = rewriteEl ?? throw new XmlException("Missing required element 'rewrite' in route element");

                    //Get the rewrite element value
                    string? replaceEl = routeEl["replace"]?.InnerText;
                    route.Alternate = replaceEl ?? throw new XmlException("Missing required element 'replace' in route element");
                }

                //add route to the collection
                routes.Add(route);
            }
        }
    }
}
