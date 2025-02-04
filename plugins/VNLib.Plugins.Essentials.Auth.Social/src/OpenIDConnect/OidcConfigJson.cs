/*
* Copyright (c) 2025 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Auth.Social
* File: OidcConfigJson.cs 
*
* OidcConfigJson.cs is part of VNLib.Plugins.Essentials.Auth.Social which is part of the larger 
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

using System.Text.Json.Serialization;

using FluentValidation;

using VNLib.Plugins.Extensions.Validation;

namespace VNLib.Plugins.Essentials.Auth.Social.OpenIDConnect
{

    internal class OidcConfigJson : OidcEndpointConfigJson
    {
        [JsonPropertyName("client_id")]
        public string? ClientId { get; init; }

        [JsonPropertyName("trust_cert")]
        public bool TrustCert { get; init; }

        [JsonPropertyName("client_secret_name")]
        public string? SecretName { get; set; }

        [JsonPropertyName("discovery_url")]
        public string? DiscoveryUrl { get; init; }

        [JsonPropertyName("timeout_ms")]
        public int TimeoutMilliseconds { get; init; } = 1000;

        [JsonPropertyName("max_redirects")]
        public int MaxRedirects { get; init; } = 5;

        [JsonPropertyName("user_agent")]
        public string UserAgent { get; init; } = "VNLib Social ODIC Client";

        [JsonPropertyName("friendly_name")]
        public string FriendlyName { get; init; } = null!;

        [JsonPropertyName("icon_url")]
        public string? IconUrl { get; init; }

        [JsonPropertyName("show_errors")]
        public bool SendErrorsToClient { get; init; } = true;

        /// <summary>
        /// The URL to redirect to after a successful upgrade
        /// </summary>
        [JsonPropertyName("redirect_url")]
        public string RedirectUrl { get; init; } = null!;

        /// <summary>
        /// The specific scope names requires for this oauth source
        /// </summary>
        [JsonPropertyName("required_scopes")]
        public string[] RequiredScopes { get; init; } = ["openid"];

        /// <summary>
        /// A value that indicates if the user will be redirected to the method's specific 
        /// redirect URL after logout
        /// </summary>
        [JsonPropertyName("require_logout_redirect")]
        public bool RequireLogoutRedirect { get; init; }

        /// <summary>
        /// Defines a prefix to add to the user ID when searching for 
        /// or creating a user in the database
        /// </summary>
        [JsonPropertyName("user_id_prefix")]
        public string? UserIdPrefix { get; init; }

        /// <summary>
        /// A value that indicates if the email address should be used as the username
        /// </summary>
        [JsonPropertyName("email_is_username")]
        public bool UseEmailAsUsername { get; init; }

        public void Validate()
        {
            InlineValidator<OidcConfigJson> val = [];

            val.RuleFor(c => c.MaxRedirects)
                .InclusiveBetween(1, 10);

            val.RuleFor(c => c.TimeoutMilliseconds)
                .InclusiveBetween(100, 60000);

            val.RuleFor(c => c.RedirectUrl)
                .NotEmpty()
                .Matches(@"^https?://[\w\-.]+(:\d+)?/.*$");

            val.RuleFor(c => c.UserAgent)
                .NotEmpty()
                .Matches(@"^[\w\-. ]+$");

            val.RuleFor(c => c.ClientId)
                .NotEmpty()
                .Matches(@"^[\w\-.]+$");

            val.RuleFor(c => c.SecretName!)
                .NotEmpty()
                .Length(1, 64)
                .Matches(@"^[\w\-.]+$");
            
            val.RuleFor(c => c.FriendlyName!)
              .NotEmpty()
              .AlphaNumericOnly();

            val.RuleFor(c => c.DiscoveryUrl)
                .Matches(@"^https?://[\w\-.]+(:\d+)?/.*$")
                .When(c => !string.IsNullOrEmpty(c.DiscoveryUrl));

            //If discovery url is not set, then the manual config is required
            val.RuleFor(c => c)
                .SetValidator(GetValidator(userInfoRequired: true))
                .When(c => string.IsNullOrEmpty(c.DiscoveryUrl));

            val.RuleFor(c => c.RequiredScopes)
                .NotEmpty()
                .ForEach(static r => r.Matches(@"^[\w\-.]+$"));
            
            val.RuleFor(c => c.UserIdPrefix)
                .NotEmpty()
                .Matches(@"^[\w\-.]+$");

            val.ValidateAndThrow(this);
        }
    }
}
