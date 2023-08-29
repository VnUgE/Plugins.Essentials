/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts.Admin
* File: UserStore.cs 
*
* UserStore.cs is part of VNLib.Plugins.Essentials.Accounts.Admin which is part of the larger 
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

using System;

using Microsoft.EntityFrameworkCore;

using VNLib.Plugins.Extensions.Data;
using VNLib.Plugins.Extensions.Data.Abstractions;

namespace VNLib.Plugins.Essentials.Accounts.Admin.Model
{

    internal class UserStore : DbStore<User>
    {
        private readonly DbContextOptions Options;

        public UserStore(DbContextOptions options)
        {
            Options = options;
        }


        ///<inheritdoc/>
        public override IDbContextHandle GetNewContext() => new UserContext(Options);

        ///<inheritdoc/>
        public override string GetNewRecordId() => string.Empty;    //IDs are not created here

        ///<inheritdoc/>
        public override IDbQueryLookup<User> QueryTable { get; } = new DbQueries();

        ///<inheritdoc/>
        public override void OnRecordUpdate(User newRecord, User currentRecord)
        {
            currentRecord.Privilages = currentRecord.Privilages;
        }

        private sealed class DbQueries : IDbQueryLookup<User>
        {
            public IQueryable<User> GetCollectionQueryBuilder(IDbContextHandle context, params string[] constraints)
            {
                return (from user in context.Set<User>()
                        orderby user.Created descending
                        select user);
            }

            public IQueryable<User> GetSingleQueryBuilder(IDbContextHandle context, params string[] constraints)
            {
                string userId = constraints[0];
                return (from user in context.Set<User>()
                        where user.UserId == userId
                        select user);
            }
        }
    }
}
