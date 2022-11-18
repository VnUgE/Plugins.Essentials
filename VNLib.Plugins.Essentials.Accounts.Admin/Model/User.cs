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
