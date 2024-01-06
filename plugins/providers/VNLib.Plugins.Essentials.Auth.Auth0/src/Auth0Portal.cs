/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Auth.Auth0
* File: Auth0Portal.cs 
*
* Auth0Portal.cs is part of VNLib.Plugins.Essentials.Auth.Auth0 which is 
* part of the larger VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Auth.Auth0 is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Auth.Auth0 is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

using System;

using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Routing;
using VNLib.Plugins.Essentials.Auth.Social;

using VNLib.Plugins.Essentials.Auth.Auth0.Endpoints;

namespace VNLib.Plugins.Essentials.Auth.Auth0
{

    [ServiceExport]
    [ConfigurationName(ConfigKey)]
    public sealed class Auth0Portal : IOAuthProvider
    {
        internal const string ConfigKey = "auth0";

        private readonly LoginEndpoint _loginEndpoint;
        private readonly LogoutEndpoint _logoutEndpoint;

        public Auth0Portal(PluginBase plugin, IConfigScope config)
        {
            //Init the login endpoint
            _loginEndpoint = plugin.Route<LoginEndpoint>();
            _logoutEndpoint = plugin.Route<LogoutEndpoint>();
        }

        ///<inheritdoc/>
        public SocialOAuthPortal[] GetPortals()
        {

            //Return the Auth0 portal
            return [
                new SocialOAuthPortal(
                    ConfigKey,
                    _loginEndpoint,
                    _logoutEndpoint
                )
            ];
            
        }
    }
}
