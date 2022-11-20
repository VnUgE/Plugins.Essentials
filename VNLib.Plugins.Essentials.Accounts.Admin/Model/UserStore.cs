/*
* Copyright (c) 2022 Vaughn Nugent
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
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Microsoft.EntityFrameworkCore;

using VNLib.Plugins.Extensions.Data;

namespace VNLib.Plugins.Essentials.Accounts.Admin.Model
{

    internal class UserStore : DbStore<User>
    {
        private readonly DbContextOptions Options;

        public UserStore(DbContextOptions options)
        {
            this.Options = options;
        }

        //Item id's are not used
        public override string RecordIdBuilder => "";

        protected override IQueryable<User> GetCollectionQueryBuilder(TransactionalDbContext context, params string[] constraints)
        {
            return (from user in context.Set<User>()
                    orderby user.Created descending
                    select user);
        }

        protected override IQueryable<User> GetSingleQueryBuilder(TransactionalDbContext context, params string[] constraints)
        {
            string userId = constraints[0];
            return (from user in context.Set<User>()
                    where user.UserId == userId
                    select user);
        }

        public override TransactionalDbContext NewContext() => new UserContext(Options);

        protected override void OnRecordUpdate(User newRecord, User currentRecord)
        {
            currentRecord.Privilages = currentRecord.Privilages;
        }
    }
}
