/*
* Copyright (c) 2022 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts.Registration
* File: RevocationContext.cs 
*
* RevocationContext.cs is part of VNLib.Plugins.Essentials.Accounts.Registration which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Accounts.Registration is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Accounts.Registration is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

using Microsoft.EntityFrameworkCore;

using VNLib.Plugins.Extensions.Data;
using VNLib.Plugins.Essentials.Accounts.Registration.TokenRevocation;

namespace VNLib.Plugins.Essentials.Accounts.Registration
{
    internal class RegistrationContext : TransactionalDbContext
    {
        public DbSet<RevokedToken> RevokedRegistrationTokens { get; set; }
        
        public RegistrationContext(DbContextOptions options) : base(options)
        {}
    }
}