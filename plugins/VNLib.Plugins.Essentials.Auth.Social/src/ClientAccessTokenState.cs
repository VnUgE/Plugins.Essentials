/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Auth.Social
* File: OAuthAccessState.cs 
*
* OAuthAccessState.cs is part of VNLib.Plugins.Essentials.Auth.Social which 
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

using System;
using System.Text.Json.Serialization;

namespace VNLib.Plugins.Essentials.Auth.Social
{
    public class OAuthAccessState : IOAuthAccessState
    {
        ///<inheritdoc/>
        [JsonPropertyName("access_token")]
        public string? Token { get; set; }
        ///<inheritdoc/>
        [JsonPropertyName("scope")]
        public string? Scope { get; set; }
        ///<inheritdoc/>
        [JsonPropertyName("token_type")]
        public string? Type { get; set; }
        ///<inheritdoc/>
        [JsonPropertyName("refresh_token")]
        public string? RefreshToken { get; set; }
        ///<inheritdoc/>
        [JsonPropertyName("id_token")]
        public string? IdToken { get; set; }
    }
}