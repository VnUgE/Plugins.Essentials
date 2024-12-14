/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Users
* File: UserEntry.cs 
*
* UserEntry.cs is part of VNLib.Plugins.Essentials.Users which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Users is free software: you can redistribute it and/or modify 
* it under the terms of the GNU General Public License as published
* by the Free Software Foundation, either version 2 of the License,
* or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Users is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
* General Public License for more details.
*
* You should have received a copy of the GNU General Public License 
* along with VNLib.Plugins.Essentials.Users. If not, see http://www.gnu.org/licenses/.
*/

using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

using Microsoft.EntityFrameworkCore;

using VNLib.Plugins.Extensions.Data;
using VNLib.Plugins.Extensions.Data.Abstractions;

namespace VNLib.Plugins.Essentials.Users.Model
{

    /// <summary>
    /// An efcore model of the lowest level of the user's entry 
    /// in the table
    /// </summary>
    [Index(nameof(UserId), IsUnique = true)]
    public class UserEntry : DbModelBase, IUserEntity
    {
        /// <summary>
        /// The Unique ID of the user
        /// </summary>
        [Key]
        [MaxLength(64)]
#pragma warning disable CS8764 // Nullability of return type doesn't match overridden member (possibly because of nullability attributes).
        public override string? Id { get; set; }
#pragma warning restore CS8764 // Nullability of return type doesn't match overridden member (possibly because of nullability attributes).

        /// <summary>
        /// The secondary ID of the user, usually an EmailAddress
        /// </summary>
        [MaxLength(64)]
        public string? UserId { get; set; }
        
        ///<inheritdoc/>
        public override DateTime Created { get; set; }
        
        ///<inheritdoc/>
        public override DateTime LastModified { get; set; }

        /// <summary>
        /// The user's privilage flags
        /// </summary>
        public long PrivilegeLevel { get; set; }
        
        /// <summary>
        /// The json-encoded raw user-data 
        /// </summary>
        public byte[]? UserData { get; set; }

        /// <summary>
        /// The optional unguarded password hash of the user entry
        /// </summary>
        [MaxLength(1000)]
        public string? PassHash { get; set; }

        /// <summary>
        /// A referrence to the <see cref="UserId"/>
        /// parameter
        /// </summary>
        [NotMapped]
        public string? EmailAddress
        {
            get => UserId;
            set => UserId = value;
        }
    }
}