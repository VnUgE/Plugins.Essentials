/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.SocialOauth
* File: OAuthSiteAdapter.cs 
*
* OAuthSiteAdapter.cs is part of VNLib.Plugins.Essentials.SocialOauth which is part of the larger 
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

using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using RestSharp;

using VNLib.Net.Rest.Client;
using VNLib.Net.Rest.Client.Construction;

namespace VNLib.Plugins.Essentials.SocialOauth
{
    /// <summary>
    /// Provides strucutred http messaging to an OAuth2 site.
    /// </summary>
    public sealed class OAuthSiteAdapter : RestSiteAdapterBase
    {
        protected override RestClientPool Pool { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="OAuthSiteAdapter"/> class.
        /// </summary>
        public OAuthSiteAdapter()
        {
            RestClientOptions poolOptions = new()
            {
                MaxTimeout = 5000,
                AutomaticDecompression = DecompressionMethods.All,
                Encoding = Encoding.UTF8,
                //disable redirects, api should not redirect
                FollowRedirects = false,
            };

            //Configure rest client to comunications to main discord api
            Pool = new(10, poolOptions);
        }

        ///<inheritdoc/>
        public override void OnResponse(RestResponse response)
        { }

        ///<inheritdoc/>
        public override Task WaitAsync(CancellationToken cancellation = default)
        {
            return Task.CompletedTask;  
        }
    }
}
