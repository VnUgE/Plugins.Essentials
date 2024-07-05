/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Auth.Social
* File: OauthClientConfig.cs 
*
* OauthClientConfig.cs is part of VNLib.Plugins.Essentials.Auth.Social which is part of the larger 
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

using System.Threading.Tasks;
using System.Threading;
using VNLib.Net.Rest.Client.Construction;
using RestSharp;

namespace VNLib.Plugins.Essentials.Auth.Social.openid
{
    /// <summary>
    /// Resolves the openid connect configuration from a discovery url
    /// </summary>
    public sealed class OpenIdResolver
    {
        private readonly RestSiteAdapterBase _defaultAdapter = RestSiteAdapterBase.CreateSimpleAdapter();

        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdResolver"/> class
        /// </summary>
        public OpenIdResolver()
        {
            _defaultAdapter.DefineSingleEndpoint()
                .WithEndpoint<DiscoveryRequest>()
                .WithMethod(Method.Get)
                .WithUrl(m => m.DiscoUrl)
                .WithHeader("Accept", "application/json")
                .OnResponse((r, rr) => rr.ThrowIfError());
        }

        /// <summary>
        /// Resolves the openid connect configuration from the discovery url
        /// </summary>
        /// <param name="discoveryUrl">The openid connect discovery url</param>
        /// <param name="cancellation">A token to cancel the resolution operation</param>
        /// <returns>A task that resolves the openid connect configuration data</returns>
        public Task<OpenIdPortalConfig?> ResolveAsync(string discoveryUrl, CancellationToken cancellation)
        {
            return _defaultAdapter.ExecuteAsync(entity: new DiscoveryRequest(discoveryUrl), cancellation)
                .AsJson<OpenIdPortalConfig>();
        }

        sealed record class DiscoveryRequest(string DiscoUrl)
        { }
    }
}
