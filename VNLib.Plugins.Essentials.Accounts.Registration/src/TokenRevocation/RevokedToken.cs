/*
* Copyright (c) 2022 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts.Registration
* File: RevokedToken.cs 
*
* RevokedToken.cs is part of VNLib.Plugins.Essentials.Accounts.Registration which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Accounts.Registration is free software: you can redistribute it and/or modify 
* it under the terms of the GNU General Public License as published
* by the Free Software Foundation, either version 2 of the License,
* or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Accounts.Registration is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
* General Public License for more details.
*
* You should have received a copy of the GNU General Public License 
* along with VNLib.Plugins.Essentials.Accounts.Registration. If not, see http://www.gnu.org/licenses/.
*/

using System;
using System.ComponentModel.DataAnnotations;

namespace VNLib.Plugins.Essentials.Accounts.Registration.TokenRevocation
{

    internal class RevokedToken
    {
        /// <summary>
        /// The time the token was revoked.
        /// </summary>
        public DateTime Created { get; set; }
        /// <summary>
        /// The token that was revoked.
        /// </summary>
        [Key]
        public string? Token { get; set; }
    }
}