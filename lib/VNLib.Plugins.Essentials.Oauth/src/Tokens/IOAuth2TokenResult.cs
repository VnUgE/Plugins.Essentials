/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Oauth
* File: IOAuth2TokenResult.cs 
*
* IOAuth2TokenResult.cs is part of VNLib.Plugins.Essentials.Oauth which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Oauth is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Oauth is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

namespace VNLib.Plugins.Essentials.Oauth.Tokens
{
    /// <summary>
    /// The result of an OAuth2Token creation
    /// </summary>
    public interface IOAuth2TokenResult
    {
        /// <summary>
        /// An optional token that can be used to identify the user
        /// </summary>
        string? IdentityToken { get; }

        /// <summary>
        /// The access token, used for authenticating requests
        /// </summary>
        string? AccessToken { get; }

        /// <summary>
        /// An optional OAuth2 refresh token, used for refreshing access tokens
        /// </summary>
        string? RefreshToken { get; }

        /// <summary>
        /// The type of token, usually "Bearer"
        /// </summary>
        string? TokenType { get; }

        /// <summary>
        /// The number of seconds until the access token expires
        /// </summary>
        int ExpiresSeconds { get; }
    }
}