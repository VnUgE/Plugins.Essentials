﻿/*
* Copyright (c) 2025 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Auth.Social
* File: OpenIdIdentityTokenJson.cs 
*
* OpenIdIdentityTokenJson.cs is part of VNLib.Plugins.Essentials.Auth.Social which is 
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


namespace VNLib.Plugins.Essentials.Auth.Social.OpenIDConnect
{
    internal sealed class OpenIdIdentityTokenJson
    {
        [JsonPropertyName("iss")]
        public string? Issuer { get; set; }

        [JsonPropertyName("aud")]
        public string? Audience { get; set; }

        [JsonPropertyName("exp")]
        public long Expiration { get; set; }

        [JsonPropertyName("iat")]
        public long IssuedAt { get; set; }

        [JsonPropertyName("sub")]
        public string? Subject { get; set; }

        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("email")]
        public string? Email { get; set; }

        [JsonPropertyName("email_verified")]
        public bool EmailVerified { get; set; }

        [JsonPropertyName("picture")]
        public string? Picture { get; set; }
    }
}
