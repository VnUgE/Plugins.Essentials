/*
* Copyright (c) 2025 Vaughn Nugent
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
using VNLib.Plugins.Extensions.Loading.Configuration;

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

            Validate.FileExists(_routeFile);

            if (_config.WatchForChanges)
            {
                FileWatcher.Subscribe(_config.RouteFile, this);
                _log.Warn("Watching for changes to route file: {file}. This is not recommended for production use", _config.RouteFile);
        }
        }

        public void OnFileChanged(FileSystemEventArgs e)
        {
            RoutesChanged?.Invoke(this, this);
        }

        ///<inheritdoc/>
        public event EventHandler<IRouteStore>? RoutesChanged;

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
            _ = memStream.Seek(0, SeekOrigin.Begin);

            //Parse elements into routes
            ParseElements(memStream, routes);
        }

        private void ParseElements(VnMemoryStream ms, ICollection<Route> routes)
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

            int count = 0;

            foreach (XmlNode routeEl in routeElements)
            {
                // Always increment count to keep track of route number for logging
                count++;

                if (routeEl.Attributes is null)
                {
                    continue;
                }

                //See if route is disabled
                string? disabledAtr = routeEl.Attributes["disabled"]?.Value;              
                if (disabledAtr != null)
                {
                    continue;
                }

                string? hostname = routeEl["hostname"]?.InnerText;

                try
                {
                    //Get the route routine value              
                    Validate.Assert(
                        Enum.TryParse(routeEl.Attributes["routine"]?.Value, ignoreCase: true, out ProcessRoutine routine),
                        "The value of the 'routine' attribute is not a valid ProcessRoutine enum value"
                    );

                    string? privilege = routeEl.Attributes["privilege"]?.Value;
                    if (string.IsNullOrEmpty(privilege))
                    {
                        privilege = 0.ToString(); //default privilege level
                    }

                    Validate.Assert(
                        ulong.TryParse(privilege, out ulong privLevel),
                        "The value of the 'privilege' attribute is not a valid unsigned 64-bit integer"
                    );

                    Route route = new()
                    {
                        Hostname        = hostname!,
                        MatchPath       = routeEl["path"]?.InnerText ?? string.Empty,
                        RewriteSearch   = routeEl["search"]?.InnerText,
                        Alternate       = routeEl["alternate"]?.InnerText,
                        Replace         = routeEl["replace"]?.InnerText,
                        Routine         = routine,
                        Privilege       = privLevel
                    };

                    route.OnValidate();

                    //add route to the collection
                    routes.Add(route);
                }
                catch(Exception ex)
                {
                    if (_config.IgnoreErrors)
                    {
                        const string errTemplate =@"
Error parsing route element for hostname '{hostname}', route {count}:
  In File: {file}
    XML: {xml}

Error: {err}
";

                        _log.Warn(
                            errTemplate,
                            hostname,
                            count,
                            _config.RouteFile,
                            routeEl.OuterXml,
                            ex
                        );
                    }
                    else if(ex is ConfigurationValidationException ce)
                    {
                    throw new ConfigurationException(  
                            message: $"Error parsing route element for hostname '{hostname}', route {count}",
                        ce
                    );
                }
                    else
                    {
                        throw;
                    }
                }
            }
            }
        }
    }
}
