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
using System.Net;
using System.Linq;
using System.Text.Json;
using System.Collections.Generic;

using VNLib.Utils.IO;
using VNLib.Net.Http;
using VNLib.Plugins.Essentials.Endpoints;
using VNLib.Plugins.Extensions.Loading;

namespace VNLib.Plugins.Essentials.Auth.Social
{
    [ConfigurationName("portals")]
    internal sealed class PortalsEndpoint : UnprotectedWebEndpoint, IDisposable
    {
        private readonly VnMemoryStream _portals;

        public PortalsEndpoint(PluginBase plugin, IConfigScope config)
        {
            string path = config.GetRequiredProperty("path", p => p.GetString()!);
            InitPathAndLog(path, plugin.Log);

            _portals = new VnMemoryStream();
        }

        public void SetPortals(IEnumerable<SocialOAuthPortal> portals)
        {
            //Convert to json
            PortalDefJson[] jsn = portals.Select(p => new PortalDefJson
            {
                id = p.PortalId,
                login = p.LoginEndpoint.Path,
                logout = p.LogoutEndpoint?.Path,
                icon = p.Base64Icon
            }).ToArray();

            //Serialize portals array to memory stream
            JsonSerializer.Serialize(_portals, jsn);

            //Set memory stream to readonly so shallow copy can be returned
            _ = VnMemoryStream.CreateReadonly(_portals);
        }

        protected override VfReturnType Get(HttpEntity entity)
        {
            //return portals array, pre-serialized
            return VirtualClose(
                entity,
                HttpStatusCode.OK,
                ContentType.Json,
                _portals!.GetReadonlyShallowCopy()
            );
        }

        void IDisposable.Dispose()
        {
            _portals?.Dispose();
        }

        private sealed class PortalDefJson
        {
            public string? id { get; set; }

            public string? login { get; set; }

            public string? logout { get; set; }

            public string? icon { get; set; }
        }
    }
}