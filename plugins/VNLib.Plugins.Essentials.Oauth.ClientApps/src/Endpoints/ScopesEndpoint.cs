/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Oauth.ClientApps
* File: ScopesEndpoint.cs 
*
* ScopesEndpoint.cs is part of VNLib.Plugins.Essentials.Oauth.ClientApps which 
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

using VNLib.Plugins.Essentials.Endpoints;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Routing;


namespace VNLib.Plugins.Essentials.Oauth.ClientApps.Endpoints
{
    [EndpointPath("{{path}}")]
    [ConfigurationName("scopes")]
    internal sealed class ScopesEndpoint(PluginBase plugin, IConfigScope config) : UnprotectedWebEndpoint
    {

        private readonly string[] _permissions = config.GetRequiredProperty<string[]>("scopes");

        protected override VfReturnType Get(HttpEntity entity)
        {
            //Return the permissions/scopes array
            return VirtualOkJson(entity, _permissions);
        }
    }
}