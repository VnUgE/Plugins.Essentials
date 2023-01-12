/*
* Copyright (c) 2022 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts.Admin
* File: UserContext.cs 
*
* UserContext.cs is part of VNLib.Plugins.Essentials.Accounts.Admin which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Accounts.Admin is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Accounts.Admin is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

using Microsoft.EntityFrameworkCore;

using VNLib.Plugins.Extensions.Data;

namespace VNLib.Plugins.Essentials.Accounts.Admin.Model
{
    internal class UserContext : TransactionalDbContext
    {
        public DbSet<User> Users { get; set; }
#nullable disable
        public UserContext(DbContextOptions options):base(options)
        {

        }
    }
}
