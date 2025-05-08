/*
* Copyright (c) 2025 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Auth.Social
* File: OpenIdConnectClient.cs 
*
* OpenIdConnectClient.cs is part of VNLib.Plugins.Essentials.Auth.Social which is part of the larger 
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
using System.Threading;
using System.Net.Http;
using System.Threading.Tasks;

using RestSharp;

using VNLib.Net.Rest.Client;
using VNLib.Net.Rest.Client.Construction;
using VNLib.Plugins.Extensions.Loading;


namespace VNLib.Plugins.Essentials.Auth.Social.OpenIDConnect
{

    internal sealed class OpenIdConnectClient
    {
        private readonly OidcAdapter _adapter;

        internal RestSiteAdapterBase Adapter => _adapter;

        public OpenIdConnectClient(OidcConfigJson config, IOnDemandSecret clientSecret)
        {
            _adapter = new(config);

            _adapter.DefineSingleEndpoint()
                .WithEndpoint<OidcDiscoveryRequest>()
                .WithUrl(r => r.DiscoveryUrl)
                .WithMethod(Method.Get)
                .WithHeader("Accept", "application/json")
                .WithHeader("User-Agent", config.UserAgent)
                .OnResponse((_, response) =>
                {

                    if (response.StatusCode != HttpStatusCode.OK)
                    {
                        throw new HttpRequestException($"Failed to fetch OIDC discovery document, status code: {response.StatusCode}");
                    }

                });

            IAsyncLazy<string?> secretResult = clientSecret
                .FetchSecretAsync()
                .ToLazy(l => l?.Result.ToString());

            //Define the token/auth endpoint
            _adapter.DefineSingleEndpoint()
                .WithEndpoint<OidcAuthenticateRequest>()
                .WithMethod(Method.Post)
                .WithUrl(c => c.AccessTokenEndpoint)
                .WithHeader("Accept", "application/json")
                .WithHeader("User-Agent", config.UserAgent)
                .WithParameter("client_id", c => config.ClientId!)
                .WithParameter("client_secret", c => secretResult.Value!)
                .WithParameter("grant_type", "authorization_code")
                .WithParameter("code", r => r.AccessCode)
                .WithParameter("redirect_uri", config.RedirectUrl)
                .OnResponse((_, response) =>
                {
                    switch (response.StatusCode)
                    {
                        //failed http request
                        case 0:
                            response.ThrowIfError();
                            break;

                        case HttpStatusCode.OK:
                        case HttpStatusCode.Accepted:
                            break;

                        default:
                            if (response.ContentLength > 0)
                            {
                                throw new HttpRequestException(
                                    $"Failed to completed authentication with status code '{response.StatusCode:d}'\n -> {response.Content}"
                                );
                            }
                            else
                            {
                                throw new HttpRequestException(
                                    $"Failed to completed authentication with status code {response.StatusCode:d}"
                                );
                            }
                    }
                });
        }

        /// <summary>
        /// Fetches the OIDC discovery document from the given address
        /// </summary>
        /// <param name="address">The ODIC source server address</param>
        /// <param name="cancellation">A token to cancel the operation</param>
        /// <returns>A task that completes with the discovery result if valid</returns>
        /// <exception cref="HttpRequestException"></exception>
        public async Task<OpenIdDiscoveryResult> DiscoverSourceAsync(string address, CancellationToken cancellation)
        {
            OidcDiscoveryRequest request = new(address);

            OpenIdDiscoveryResult? response = await _adapter
                .ExecuteAsync(request, cancellation)
                .AsJson<OpenIdDiscoveryResult>();

            response?.Validate();

            return response!;
        }

        public async Task<OpenIdTokenResponse> ExchangeCodeForTokenAsync(string address, string accessCode, CancellationToken cancellation)
        {
            OidcAuthenticateRequest request = new(address, accessCode);

            OpenIdTokenResponse? response = await _adapter
                .ExecuteAsync(request, cancellation)
                .AsJson<OpenIdTokenResponse>();
            
            if (response?.Error != null)
            {
                throw new HttpRequestException($"Failed to exchange code for token: {response.ErrorDescription}");            
            }

            return response!;
        }

        private sealed record OidcDiscoveryRequest(string DiscoveryUrl);

        private sealed record OidcAuthenticateRequest(string AccessTokenEndpoint, string AccessCode);

        private sealed class OidcAdapter : RestSiteAdapterBase
        {
            protected override RestClientPool Pool { get; }

            public OidcAdapter(OidcConfigJson config)
            {
                Pool = new RestClientPool(maxClients: 2, new RestClientOptions
                {
                    AutomaticDecompression = DecompressionMethods.All,
                    Encoding        = System.Text.Encoding.UTF8,
                    Timeout         = TimeSpan.FromMilliseconds(config.TimeoutMilliseconds),
                    UserAgent       = config.UserAgent,
                    MaxRedirects    = config.MaxRedirects,

                    //Allow self signed certs if the user wants
                    RemoteCertificateValidationCallback = (_, _, _, errs) => config.TrustCert || errs == System.Net.Security.SslPolicyErrors.None
                });
            }

            public override void OnResponse(RestResponse response)
            { }

            public override Task WaitAsync(CancellationToken cancellation = default)
            {
                return Task.CompletedTask;
            }
        }

    }
}
