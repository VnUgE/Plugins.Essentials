/*
* Copyright (c) 2025 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Auth.Social
* File: OidcEndpointConfigJson.cs 
*
* OidcEndpointConfigJson.cs is part of VNLib.Plugins.Essentials.Auth.Social which is
* part of the larger VNLib collection of libraries and utilities.
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

namespace VNLib.Plugins.Essentials.Auth.Social.OpenIDConnect
{
    internal class OidcEndpointConfigJson
    {
        public static IValidator<OidcEndpointConfigJson> GetValidator(bool userInfoRequired)
        {
            InlineValidator<OidcEndpointConfigJson> val = [];

            val.RuleFor(r => r.Issuer)
                .NotEmpty()
                .Matches(@"^https?://[\w\-.]+(:\d+)?/?.*$");

            val.RuleFor(r => r.AuthorizationEndpoint)
                .NotEmpty()
                .Matches(@"^https?://[\w\-.]+(:\d+)?/.*$");

            val.RuleFor(r => r.TokenEndpoint)
                .NotEmpty()
                .Matches(@"^https?://[\w\-.]+(:\d+)?/.*$");

            val.RuleFor(c => c.UserInfoEndpoint)
                .Matches(@"^https?://[\w\-.]+(:\d+)?/.*$")
                .WithMessage("User info endpoint must be a valid URL")
                .When(c => !string.IsNullOrEmpty(c.UserInfoEndpoint) || userInfoRequired);

            val.RuleFor(c => c.JwksUri)
                .Matches(@"^https?://[\w\-.]+(:\d+)?/.*$")
                .WithMessage("JWKS URI must be a valid URL")
                .When(c => !string.IsNullOrEmpty(c.JwksUri));

            return val;
        }

        [JsonPropertyName("issuer")]
        public string Issuer { get; init; } = string.Empty;

        [JsonPropertyName("authorization_endpoint")]
        public string AuthorizationEndpoint { get; set; } = string.Empty;

        [JsonPropertyName("token_endpoint")]
        public string TokenEndpoint { get; set; } = string.Empty;

        [JsonPropertyName("userinfo_endpoint")]
        public string? UserInfoEndpoint { get; set; }

        [JsonPropertyName("jwks_uri")]
        public string JwksUri { get; set; } = string.Empty;
    }
}
