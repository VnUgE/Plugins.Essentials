/*
* Copyright (c) 2025 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Auth.Social
* File: OpenIdDiscoveryResult.cs 
*
* OpenIdDiscoveryResult.cs is part of VNLib.Plugins.Essentials.Auth.Social which 
* is part of the larger VNLib collection of libraries and utilities.
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
    internal sealed class OpenIdDiscoveryResult : OidcEndpointConfigJson
    {
        [JsonPropertyName("response_types_supported")]
        public string[] ResponseTypesSupported { get; set; } = [];

        [JsonPropertyName("subject_types_supported")]
        public string[] SubjectTypesSupported { get; set; } = [];

        [JsonPropertyName("id_token_signing_alg_values_supported")]
        public string[] IdTokenSigningAlgValuesSupported { get; set; } = [];

        [JsonPropertyName("scopes_supported")]
        public string[] ScopesSupported { get; set; } = [];

        public void Validate()
        {
            InlineValidator<OpenIdDiscoveryResult> val = [];

            _ = val.RuleFor(c => c)
                .SetValidator(GetValidator());

            _ = val.RuleFor(c => c.ResponseTypesSupported)
                .NotEmpty()
                //Must contain code and token types
                .ForEach(p => p.Matches(@"^code|token$"))
                .WithMessage("Response type must contain code and or token");

            _ = val.RuleFor(c => c.ScopesSupported)
                .ForEach(p => p.Matches(@"^[\w\-.]+$"))
                .WithMessage("Scope must be a valid string")
                .When(c => c.ScopesSupported?.Length > 0);

            val.ValidateAndThrow(this);
        }
    }
}
