/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Auth.Social
* File: SocialOAuthPortal.cs 
*
* SocialOAuthPortal.cs is part of VNLib.Plugins.Essentials.Auth.Social which is part of the larger 
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

namespace VNLib.Plugins.Essentials.Auth.Social
{
    /// <summary>
    /// Defines a single oauth social login portal
    /// </summary>
    /// <param name="PortalId"> The unique identifier for the portal </param>
    /// <param name="LoginEndpoint"> Required login endpoint to advertise to the client </param>
    /// <param name="LogoutEndpoint"> Optional logout endpoint to advertise to the client </param>
    /// <param name="Base64Icon">Optional base64 image icon src for the client to load and display</param>
    public record SocialOAuthPortal(string PortalId, IEndpoint LoginEndpoint, IEndpoint? LogoutEndpoint, string? Base64Icon);
}