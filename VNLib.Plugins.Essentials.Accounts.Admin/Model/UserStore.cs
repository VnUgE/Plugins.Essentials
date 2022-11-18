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
