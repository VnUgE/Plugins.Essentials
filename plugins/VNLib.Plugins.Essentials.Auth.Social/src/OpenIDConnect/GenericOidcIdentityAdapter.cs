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
        protected static readonly string[] AuthErrorArray = [ "An error occurred during authentication" ];

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
        public virtual async ValueTask<OidcLoginDataResult> GetLoginDataAsync(SocialMethodState state, OpenIdTokenResponse token)
        {
            using JsonWebToken openIdToken = JsonWebToken.Parse(token.IdToken);
            OpenIdIdentityTokenJson? idToken = openIdToken.GetPayload<OpenIdIdentityTokenJson>();

            if (idToken is null)
            {
                return new OidcLoginDataResult
                {
                    IsValid = false,
                    Errors = AuthErrorArray 
                };
            }

            //Validate the token response
            ValidationResult result = _idTokenValidator.Validate(idToken);
            if (!result.IsValid)
            {
                return new OidcLoginDataResult
                {
                    IsValid = false,
                    Errors = result.Errors.Select(e => e.ErrorMessage).ToArray()
                };
            }

            //Check if token is expired
            if (idToken.Expiration < state.Entity.RequestedTimeUtc.ToUnixTimeSeconds())
            {
                return new OidcLoginDataResult
                {
                    IsValid = false,
                    Errors = AuthErrorArray
                };
            }

            //Email is being used as an authoritative username
            if (_config.UseEmailAsUsername)
            {
                if (string.IsNullOrWhiteSpace(idToken.Email))
                {
                    /*
                     * If no email address is present in the token, fallback to the 
                     * user-info endpoint to fetch the email address. If the user-info endpoint
                     * is not available, then the login data is invalid.
                     */

                    OidcNewUserDataResult userData = await GetNewUserDataAsync(state, token);

                    return new OidcLoginDataResult
                    {
                        Errors       = userData.Errors,
                        IsValid     = userData.IsValid,
                        Username    = userData.EmailAddress
                    };
                }
                else if (idToken.EmailVerified)
                {
                    return new OidcLoginDataResult
                    {
                        IsValid     = true,
                        Errors       = null,
                        Username    = idToken.Email
                    };
                }
                else
                {
                    return new OidcLoginDataResult
                    {
                        IsValid = false,
                        Errors   = ["Email address is required"]
                    };
                }
            }

            /*
             * Platform id's may be unsafe to enter in the database so 
             * a safe user-id must be generated from the platform id.
             */
            else if (!string.IsNullOrWhiteSpace(_config.UserIdPrefix))
            {
                //Prepend a prefix to the user id if it was set by the configuration
                return new OidcLoginDataResult
                {
                    IsValid     = true,
                    Errors       = null,
                    Username    = state.Users.ComputeSafeUserId($"{_config.UserIdPrefix}|{idToken.Subject}")
                };
            }
            else
            {
                return new OidcLoginDataResult
                {
                    IsValid     = true,
                    Errors       = null,
                    Username    = state.Users.ComputeSafeUserId(idToken.Subject!)
                };
            }
        }

        public async Task<OidcNewUserDataResult> GetNewUserDataAsync(SocialMethodState state, OpenIdTokenResponse token)
        {
            using JsonWebToken openIdToken = JsonWebToken.Parse(token.IdToken);
            using JsonDocument idDocument = openIdToken.GetPayload();

            if (TryGetEmailFromToken(idDocument, out string? email))
            {
                string platformId = idDocument.RootElement.GetProperty("sub").GetString();

                return new OidcNewUserDataResult
                {
                    IsValid         = true,
                    Errors           = null,
                    EmailAddress    = email,
                    SafeUserId      = state.Users.ComputeSafeUserId(platformId!) 
                };
            }
            //User info endpoint must be available
            else if (string.IsNullOrEmpty(_config.UserInfoEndpoint))
            {
                return new OidcNewUserDataResult
                {
                    IsValid         = false,
                    Errors          = ["User info endpoint is not available"],
                    SafeUserId      = null,
                    EmailAddress    = null
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
                        IsValid         = false,
                        Errors          = ["Failed to fetch user info"],
                        SafeUserId      = null,
                        EmailAddress    = null
                    };
                }

                UserInfoJson? userInfo = JsonSerializer.Deserialize<UserInfoJson>(response.RawBytes);

                if (userInfo is null)
                {
                    return new OidcNewUserDataResult
                    {
                        IsValid         = false,
                        Errors          = ["Failed to fetch user info"],
                        SafeUserId      = null,
                        EmailAddress    = null
                    };
                }
                else
                {
                    return new OidcNewUserDataResult
                    {
                        IsValid         = true,
                        Errors          = null,
                        SafeUserId      = state.Users.ComputeSafeUserId(userInfo.Subject!),
                        EmailAddress    = userInfo.Email,
                        Name            = userInfo.Subject
                    };
                }
            }

            return new OidcNewUserDataResult
            {
                IsValid         = false,
                Errors          = ["Failed to fetch user info"],
                SafeUserId      = null,
                EmailAddress    = null
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

                //If an email is specified, it must be a valid email
                RuleFor(r => r.Email)
                    .EmailAddress()
                    .When(r => !string.IsNullOrEmpty(r.Email));
            }
        }

        private sealed record UserinfoGetRequest(string AccessToken) { }

        private sealed record UserInfoJson
        {
            [JsonPropertyName("sub")]
            public string? Subject { get; init; }

            [JsonPropertyName("email")]
            public string Email { get; init; } = null!;

            [JsonPropertyName("verified")]
            public bool Verified { get; init; }

            [JsonPropertyName("email_verified")]
            public bool EmailVerified
            {
                init => Verified = value;
            }
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

        private sealed class NewUserDataValidator : AbstractValidator<OidcNewUserDataResult>
        {
            public NewUserDataValidator()
            {
                RuleFor(r => r.SafeUserId)
                    .NotEmpty()
                    .Matches(@"^[\w\-.]+$")
                    .MaximumLength(128);

                RuleFor(r => r.EmailAddress)
                    .NotEmpty()
                    .EmailAddress()
                    .MaximumLength(256);

                RuleFor(r => r.Name)
                    .Matches(@"^[\w\-. ]+$")
                    .When(r => r != null);
            }
        }
    }
}
