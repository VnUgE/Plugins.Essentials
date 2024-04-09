/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts.AppData
* File: DataRecord.cs 
*
* DataRecord.cs is part of VNLib.Plugins.Essentials.Accounts.AppData which 
* is part of the larger VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Accounts is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Accounts is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

using System;
using System.ComponentModel.DataAnnotations;

using VNLib.Plugins.Extensions.Data.Abstractions;
using VNLib.Plugins.Extensions.Data;

namespace VNLib.Plugins.Essentials.Accounts.AppData.Stores.Sql
{

#nullable disable
    internal sealed class DataRecord : DbModelBase, IUserEntity
    {
        [Key]
        [MaxLength(64)]
        public override string Id { get; set; }

        [MaxLength(64)]
        public string RecordKey { get; set; }

        [MaxLength(64)]
        public string UserId { get; set; }

        public override DateTime Created { get; set; }

        public override DateTime LastModified { get; set; }

        [MaxLength(int.MaxValue)]   //Should defailt to MAX it set to very large number
        public byte[] Data { get; set; }

        /// <summary>
        /// The FNV-1a checksum of the data
        /// </summary>
        public long Checksum { get; set; }
    }
}
