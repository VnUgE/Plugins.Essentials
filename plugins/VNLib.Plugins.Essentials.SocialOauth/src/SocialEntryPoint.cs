/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.SocialOauth
* File: SocialEntryPoint.cs 
*
* SocialEntryPoint.cs is part of VNLib.Plugins.Essentials.SocialOauth which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.SocialOauth is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.SocialOauth is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

using System;

using VNLib.Utils.Logging;
using VNLib.Plugins.Essentials.SocialOauth.Endpoints;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Routing;

namespace VNLib.Plugins.Essentials.SocialOauth
{
    public sealed class SocialEntryPoint : PluginBase
    {

        public override string PluginName => "Essentials.SocialOauth";

        protected override void OnLoad()
        {
            //Get the discord oauth config from the config file
            if (this.HasConfigForType<DiscordOauth>())
            {
                //Add the discord login endpoint
                this.Route<DiscordOauth>();
                Log.Information("Discord social OAuth authentication loaded");
            }
            if (this.HasConfigForType<GitHubOauth>())
            {
                //Add the github login endpoint
                this.Route<GitHubOauth>();
                Log.Information("Github social OAuth authentication loaded");
            }

            if (this.HasConfigForType<Auth0>())
            {
                //Add the auth0 login endpoint
                this.Route<Auth0>();
                Log.Information("Auth0 social OAuth authentication loaded");
            }
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