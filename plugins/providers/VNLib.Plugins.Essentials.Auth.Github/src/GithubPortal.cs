/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Auth.Github
* File: GithubPortal.cs 
*
* GithubPortal.cs is part ofVNLib.Plugins.Essentials.Auth.Githubwhich is 
* part of the larger VNLib collection of libraries and utilities.
*
*VNLib.Plugins.Essentials.Auth.Githubis free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
*VNLib.Plugins.Essentials.Auth.Githubis distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Routing;
using VNLib.Plugins.Essentials.Auth.Social;

using VNLib.Plugins.Essentials.Auth.Github.Endpoints;

namespace VNLib.Plugins.Essentials.Auth.Github
{

    [ServiceExport]
    [ConfigurationName(ConfigKey)]
    public sealed class GithubPortal(PluginBase plugin) : IOAuthProvider
    {
        internal const string ConfigKey = "github";

        private readonly GitHubOauth _loginEndpoint = plugin.Route<GitHubOauth>();

        ///<inheritdoc/>
        public SocialOAuthPortal[] GetPortals()
        {
            //Return the github portal
            return [
                new SocialOAuthPortal(
                    ConfigKey,
                    _loginEndpoint,
                    null
                )
            ];
            
        }
    }
}
