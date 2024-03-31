/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts.AppData
* File: UserRecordDbContext.cs 
*
* UserRecordDbContext.cs is part of VNLib.Plugins.Essentials.Accounts.AppData which 
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

using Microsoft.EntityFrameworkCore;

using VNLib.Plugins.Extensions.Data;
using VNLib.Plugins.Extensions.Loading.Sql;

namespace VNLib.Plugins.Essentials.Accounts.AppData.Stores.Sql
{
    internal sealed class UserRecordDbContext : DBContextBase, IDbTableDefinition
    {
        public DbSet<DataRecord> UserDataRecords { get; set; }

        public UserRecordDbContext(DbContextOptions options) : base(options)
        { }

        public UserRecordDbContext()
        { }

        public void OnDatabaseCreating(IDbContextBuilder builder, object? userState)
        {
            //Define the table for the data records
            builder.DefineTable<DataRecord>(nameof(UserDataRecords), table =>
            {
                //Define table columns
                table.WithColumn(p => p.Id).AllowNull(false);
                table.WithColumn(p => p.Version).TimeStamp();
                table.WithColumn(p => p.RecordKey).AllowNull(false);
                table.WithColumn(p => p.UserId).AllowNull(false);
                table.WithColumn(p => p.Created);
                table.WithColumn(p => p.LastModified);
                table.WithColumn(p => p.Data);
                table.WithColumn(p => p.Checksum);
            });
        }
    }
}
