/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Auth.Social
* File: PortalsEndpoint.cs 
*
* PortalsEndpoint.cs is part of VNLib.Plugins.Essentials.Auth.Social which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Auth.Social is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Auth.Social is distributed in the hope that it will be useful,
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

using VNLib.Plugins.Essentials.Endpoints;
using VNLib.Plugins.Extensions.Loading;


namespace VNLib.Plugins.Essentials.Auth.Social
{
    [ConfigurationName("portals")]
    internal sealed class PortalsEndpoint : UnprotectedWebEndpoint
    {
        private PortalDefJson[] _portals;

        public PortalsEndpoint(PluginBase plugin, IConfigScope config)
        {
            string path = config.GetRequiredProperty("path", p => p.GetString()!);
            InitPathAndLog(path, plugin.Log);

            //Empty array by default
            _portals = [];
        }

        public void SetPortals(IEnumerable<SocialOAuthPortal> portals)
        {
            //Convert to json
            _portals = portals.Select(p => new PortalDefJson
            {
                id = p.PortalId,
                login = p.LoginEndpoint.Path,
                logout = p.LogoutEndpoint?.Path,
            }).ToArray();
        }

        protected override VfReturnType Get(HttpEntity entity)
        {
            //return portals array as json
            return VirtualOkJson(entity, _portals);
        }

        private sealed class PortalDefJson
        {
            public string? id { get; set; }

            public string? login { get; set; }

            public string? logout { get; set; }
        }
    }
}