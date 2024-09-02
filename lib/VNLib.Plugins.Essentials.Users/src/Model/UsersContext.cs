/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Users
* File: UsersContext.cs 
*
* UsersContext.cs is part of VNLib.Plugins.Essentials.Users which is part of the larger 
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

using Microsoft.EntityFrameworkCore;

using VNLib.Plugins.Essentials.Accounts;
using VNLib.Plugins.Extensions.Data;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Sql;

namespace VNLib.Plugins.Essentials.Users.Model
{
    /// <summary>
    /// The Efcore transactional database context
    /// </summary>
    public class UsersContext : DBContextBase, IDbTableDefinition
    {
        /// <summary>
        /// The Users table
        /// </summary>
        public DbSet<UserEntry> Users { get; set; }

#nullable disable

        public UsersContext()
        { }

        public UsersContext(DbContextOptions options):base(options)
        { }

#nullable enable
      

        ///<inheritdoc/>
        public void OnDatabaseCreating(IDbContextBuilder builder, object? userState)
        {
            PluginBase plugin = (userState as PluginBase)!;

            //Try to get the configuration for the users implementation
            IConfigScope? userConfig = plugin.TryGetConfig("users");

            //Maxium char size in most dbs
            int userMaxLen = userConfig?.GetValueOrDefault<int>("max_data_size", 8000) ?? 8000;

            //Define user-table from the users dbset field
            builder.DefineTable<UserEntry>(nameof(Users), table =>
            {
                table.WithColumn(p => p.Id).AllowNull(false);
                table.WithColumn(p => p.UserId).AllowNull(false);
                table.WithColumn(p => p.LastModified);
                table.WithColumn(p => p.Created);
                table.WithColumn(p => p.PassHash);
                table.WithColumn(p => p.PrivilegeLevel).AllowNull(false).WithDefault(AccountUtil.MINIMUM_LEVEL);
                table.WithColumn(p => p.UserData).MaxLength(userMaxLen);
                table.WithColumn(p => p.Version);
            });
        }
    }
}