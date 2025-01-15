/*
* Copyright (c) 2025 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Auth.Social
* File: SocialUpgradeResult.cs 
*
* SocialUpgradeResult.cs is part of VNLib.Plugins.Essentials.Auth.Social which 
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

using System.Text.Json;

namespace VNLib.Plugins.Essentials.Auth.Social.Controllers
{
    /// <summary>
    /// The result of a call to <see cref="ISocialOauthMethod.OnUpgradeAsync(SocialMethodState, JsonElement)"/>
    /// </summary>
    public sealed record SocialUpgradeResult
    {
        /// <summary>
        /// Indicates if the upgrade was successful
        /// </summary>
        public required bool Success { get; init; }

        /// <summary>
        /// The URL to redirect the user to for authentication
        /// </summary>
        public required string? AuthUrl { get; init; }

        /// <summary>
        /// Optional signed state data that will be stored and returned on 
        /// calls to <see cref="ISocialOauthMethod.OnAuthenticateAsync(SocialMethodState, Accounts.IClientSecInfo, JsonElement, JsonElement)"/>
        /// </summary>
        public required object? StateData { get; init; }
    }
}
