/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Auth.Discord
* File: DiscordPortal.cs 
*
* DiscordPortal.cs is part of VNLib.Plugins.Essentials.Auth.Discord which is 
* part of the larger VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Auth.Discord is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Auth.Discord is distributed in the hope that it will be useful,
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

using VNLib.Plugins.Essentials.Auth.Discord.Endpoints;

namespace VNLib.Plugins.Essentials.Auth.Discord
{

    [ServiceExport]
    [ConfigurationName(ConfigKey)]
    public sealed class DiscordPortal(PluginBase plugin, IConfigScope config) : IOAuthProvider
    {
        internal const string ConfigKey = "discord";

        private readonly DiscordOauth _loginEndpoint = plugin.Route<DiscordOauth>();

        ///<inheritdoc/>
        public SocialOAuthPortal[] GetPortals()
        {
            string? base64IconData = config.GetValueOrDefault("icon", p => p.GetString()!, null);

            //Return the Discord portal
            return [
                new SocialOAuthPortal(
                    ConfigKey,
                    _loginEndpoint,
                    LogoutEndpoint: null,
                    base64IconData
                )
            ];
        }
    }
}
