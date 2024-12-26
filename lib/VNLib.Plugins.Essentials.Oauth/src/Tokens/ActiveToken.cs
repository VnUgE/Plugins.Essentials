/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Oauth
* File: ActiveToken.cs 
*
* ActiveToken.cs is part of VNLib.Plugins.Essentials.Oauth which is part of the larger 
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

using System;

using VNLib.Plugins.Extensions.Data;

namespace VNLib.Plugins.Essentials.Oauth.Tokens
{
    /// <summary>
    /// Represents a token record in the database
    /// </summary>
    public class ActiveToken : DbModelBase
    {
        ///<inheritdoc/>
        public override string Id { get; set; } = string.Empty;

        ///<inheritdoc/>
        public override DateTime Created { get; set; }

        ///<inheritdoc/>
        public override DateTime LastModified { get; set; }

        /// <summary>
        /// A ID of the applicaiton this token was issued for
        /// </summary>
        public string? ApplicationId { get; set; }

        /// <summary>
        /// An optional OAuth2 refresh token, used for refreshing access tokens
        /// </summary>
        public string? RefreshToken { get; set; }
    }
}
