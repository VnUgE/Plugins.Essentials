/*
* Copyright (c) 2025 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Auth.Social
* File: OpenIdTokenResponse.cs 
*
* OpenIdTokenResponse.cs is part of VNLib.Plugins.Essentials.Auth.Social which is
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
    internal sealed class OpenIdTokenResponse
    {
        
        [JsonPropertyName("access_token")]
        public string? Token { get; set; }

        [JsonPropertyName("scope")]
        public string? Scope { get; set; }
       
        [JsonPropertyName("token_type")]
        public string? Type { get; set; }
      
        [JsonPropertyName("refresh_token")]
        public string? RefreshToken { get; set; }
        
        [JsonPropertyName("id_token")]
        public string? IdToken { get; set; }

        [JsonPropertyName("error")]
        public string? Error { get; set; }

        [JsonPropertyName("error_description")]
        public string? ErrorDescription { get; set; }
    }
}
