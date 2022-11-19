/*
* Copyright (c) 2022 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts.Admin
* File: User.cs 
*
* User.cs is part of VNLib.Plugins.Essentials.Accounts.Admin which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Accounts.Admin is free software: you can redistribute it and/or modify 
* it under the terms of the GNU General Public License as published
* by the Free Software Foundation, either version 2 of the License,
* or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Accounts.Admin is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
* General Public License for more details.
*
* You should have received a copy of the GNU General Public License 
* along with VNLib.Plugins.Essentials.Accounts.Admin. If not, see http://www.gnu.org/licenses/.
*/

using System;
using System.ComponentModel.DataAnnotations.Schema;

using VNLib.Plugins.Extensions.Data;
using VNLib.Plugins.Extensions.Data.Abstractions;

namespace VNLib.Plugins.Essentials.Accounts.Admin.Model
{
    internal class User : DbModelBase, IUserEntity
    {
        public string? UserId { get; set; }
        //Users's do not have unique id values
        [NotMapped]
        public override string Id
        {
            get => UserId!;
            set => UserId = value;
        }
        public override DateTime Created { get; set; }
        //Do not map the last modified, user table does not have a last modified field.
        [NotMapped]
        public override DateTime LastModified { get; set; }

        public ulong Privilages { get; set; }
    }
}
