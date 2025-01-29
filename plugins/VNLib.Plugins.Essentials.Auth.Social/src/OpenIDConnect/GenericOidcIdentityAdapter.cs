/*
* Copyright (c) 2025 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Auth.Social
* File: OpenIdConnectMethod.cs 
*
* OpenIdConnectMethod.cs is part of VNLib.Plugins.Essentials.Auth.Social which is part of the larger 
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
using System.Net.Http;
using System.Threading.Tasks;
using System.Text.Json;
using System.Text.Json.Serialization;

using RestSharp;

using FluentValidation;
using FluentValidation.Results;

using VNLib.Utils.Extensions;
using VNLib.Hashing.IdentityUtility;
using VNLib.Net.Rest.Client.Construction;

namespace VNLib.Plugins.Essentials.Auth.Social.OpenIDConnect
{
    internal class GenericOidcIdentityAdapter : IOidcIdenityAdapter
    {
        protected const string AuthErrorString = "An error occurred during authentication";

        private readonly OidcConfigJson _config;
        private readonly OpenIdConnectClient _client;
        private readonly IdTokenValidator _idTokenValidator;

        public GenericOidcIdentityAdapter(OidcConfigJson config, OpenIdConnectClient client)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _client = client ?? throw new ArgumentNullException(nameof(client));

            _idTokenValidator = new IdTokenValidator(config.ClientId, _config);

            client.Adapter.DefineSingleEndpoint()
                .WithEndpoint<UserinfoGetRequest>()
                .WithMethod(Method.Get)
                .WithUrl(config.UserInfoEndpoint!)
                .WithHeader("Authorization", p => $"Bearer {p.AccessToken}")
                .WithHeader("Accept", "application/json")
                .WithHeader("User-Agent", config.UserAgent)
                .OnResponse((_, response) =>
                {
                    if (response.StatusCode != HttpStatusCode.OK)
                    {
                        throw new HttpRequestException($"Failed to fetch user info, status code: {response.StatusCode}");
                    }
                });
        }

        ///<inheritdoc/>
        public virtual ValueTask<OidcLoginDataResult> GetLoginDataAsync(SocialMethodState state, OpenIdTokenResponse token)
        {
            OidcLoginDataResult result = GetUserInfoFromToken(state, token);
            return ValueTask.FromResult(result);
        }

        public async Task<OidcNewUserDataResult> GetNewUserDataAsync(SocialMethodState state, OpenIdTokenResponse token)
        {
            using JsonWebToken openIdToken = JsonWebToken.Parse(token.IdToken);
            using JsonDocument idDocument = openIdToken.GetPayload();

            if (TryGetEmailFromToken(idDocument, out string? email))
            {
                return new OidcNewUserDataResult
                {
                    IsValid         = true,
                    Error           = null,
                    EmailAddress    = email
                };
            }
            //User info endpoint must be available
            else if (string.IsNullOrEmpty(_config.UserInfoEndpoint))
            {
                return new OidcNewUserDataResult
                {
                    IsValid     = false,
                    Error       = "User info endpoint is not available"
                };
            }
            else
            {
                return await FetchUserDataAsync(state, token);
            }
        }

        private async Task<OidcNewUserDataResult> FetchUserDataAsync(SocialMethodState state, OpenIdTokenResponse token)
        {
            RestResponse response = await _client.Adapter.ExecuteAsync<UserinfoGetRequest>(
                entity: new (token.Token),
                state.Entity.EventCancellation
            );

            if (response.StatusCode == HttpStatusCode.OK)
            {
                //Ensure the response is json
                if (response.ContentType != "application/json")
                {
                    return new OidcNewUserDataResult
                    {
                        IsValid = false,
                        Error = "Failed to fetch user info"
                    };
                }

                UserInfoJson? userInfo = JsonSerializer.Deserialize<UserInfoJson>(response.RawBytes);

                if (userInfo is null)
                {
                    return new OidcNewUserDataResult
                    {
                        IsValid = false,
                        Error = "Failed to fetch user info"
                    };
                }

                return new OidcNewUserDataResult
                {
                    IsValid         = true,
                    Error           = null,
                    EmailAddress    = userInfo.Email,
                    Name            = userInfo.Subject
                };
            }

            return new OidcNewUserDataResult
            {
                IsValid = false,
                Error = "Failed to fetch user info"
            };
        }

        private static bool TryGetEmailFromToken(JsonDocument idTokenPayload, out string? email)
        {
            if (idTokenPayload.RootElement.TryGetProperty("email", out JsonElement emailElement))
            {
                email = emailElement.GetString();
                return true;
            }

            email = null;
            return false;
        }

        private protected virtual OidcLoginDataResult GetUserInfoFromToken(SocialMethodState state, OpenIdTokenResponse token)
        {
            using JsonWebToken openIdToken = JsonWebToken.Parse(token.IdToken);
            OpenIdIdentityTokenJson? idToken = openIdToken.GetPayload<OpenIdIdentityTokenJson>();

            if (idToken is null)
            {
                return new OidcLoginDataResult
                {
                    IsValid = false,
                    Error = AuthErrorString
                };
            }

            //Validate the token response
            ValidationResult result = _idTokenValidator.Validate(idToken);
            if (!result.IsValid)
            {
                return new OidcLoginDataResult
                {
                    IsValid = false,
                    Error = result.Errors.First().ErrorMessage
                };
            }

            //Check if token is expired
            if (idToken.Expiration < state.Entity.RequestedTimeUtc.ToUnixTimeSeconds())
            {
                return new OidcLoginDataResult
                {
                    IsValid = false,
                    Error = AuthErrorString
                };
            }

            //Prepend a prefix to the user id if it was set by the configuration
            if (!string.IsNullOrWhiteSpace(_config.UserIdPrefix))
            {
                idToken.Subject = $"{_config.UserIdPrefix}|{idToken.Subject}";
            }

            return new OidcLoginDataResult
            {
                IsValid     = true,
                Error       = null,
                PlatformId  = idToken.Subject!
            };
        }

        private sealed class IdTokenValidator : AbstractValidator<OpenIdIdentityTokenJson>
        {
            public IdTokenValidator(string clientId, OidcEndpointConfigJson serverInfo)
            {
                //Audience tokem must match the client id
                RuleFor(r => r.Audience)
                    .NotNull()
                    .Must(aud => aud!.Contains(clientId, StringComparer.OrdinalIgnoreCase));

                RuleFor(r => r.Issuer)
                    .NotEmpty()
                    .Equal(serverInfo.Issuer, StringComparer.OrdinalIgnoreCase);

                RuleFor(r => r.Subject)
                    .NotEmpty();
            }
        }

        private sealed record UserinfoGetRequest(string AccessToken) { }

        private sealed record UserInfoJson
        {
            [JsonPropertyName("sub")]
            public string? Subject { get; set; }

            [JsonPropertyName("email")]
            public string Email { get; set; } = null!;

            [JsonPropertyName("verified")]
            public bool Verified { get; set; }
        }

        private sealed class UserinfoResultValidator : AbstractValidator<UserInfoJson>
        {
            public UserinfoResultValidator()
            {
                RuleFor(r => r.Subject)
                    .NotEmpty();

                RuleFor(r => r.Email)
                    .NotEmpty()
                    .EmailAddress();
            }
        }
    }
}
