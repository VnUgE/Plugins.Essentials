/*
* Copyright (c) 2022 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.SocialOauth
* File: IOAuthAccessState.cs 
*
* IOAuthAccessState.cs is part of VNLib.Plugins.Essentials.SocialOauth which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.SocialOauth is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.SocialOauth is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

#nullable enable

namespace VNLib.Plugins.Essentials.SocialOauth
{
    /// <summary>
    /// An object that represents an OAuth2 access token in its 
    /// standard form.
    /// </summary>
    public interface IOAuthAccessState
    {
        /// <summary>
        /// The OAuth2 access token
        /// </summary>
        public string? Token { get; set; }
        /// <summary>
        /// Token grant scope
        /// </summary>
        string? Scope { get; set; }
        /// <summary>
        /// The OAuth2 token type, usually 'Bearer'
        /// </summary>
        string? Type { get; set; }
        /// <summary>
        /// Optional refresh token
        /// </summary>
        string? RefreshToken { get; set; }

        /// <summary>
        /// Optional ID OIDC token
        /// </summary>
        string? IdToken { get; set; }
    }
}