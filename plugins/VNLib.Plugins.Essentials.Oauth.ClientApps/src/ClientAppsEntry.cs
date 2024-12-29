/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Oauth.ClientApps
* File: ClientAppsEntry.cs 
*
* ClientAppsEntry.cs is part of VNLib.Plugins.Essentials.Oauth.ClientApps which 
* is part of the larger VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Oauth.ClientApps is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Oauth.ClientApps is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

using System;

using VNLib.Utils.Logging;
using VNLib.Plugins.Extensions.Loading.Routing;
using VNLib.Plugins.Essentials.Oauth.ClientApps.Endpoints;

namespace VNLib.Plugins.Essentials.Oauth.ClientApps
{
    public sealed class ClientAppsEntry : PluginBase
    {
        public override string PluginName => "Essentials.OAuth2.ClientApps";

        protected override void OnLoad()
        {
            //Route the applications endpoint
            this.Route<ApplicationEndpoint>();
            this.Route<ScopesEndpoint>();

            Log.Information("Plugin Loaded");
        }

        protected override void OnUnLoad()
        {
            Log.Information("Plugin unloaded");
        }

        protected override void ProcessHostCommand(string cmd)
        {
            throw new NotImplementedException();
        }
    }
}
