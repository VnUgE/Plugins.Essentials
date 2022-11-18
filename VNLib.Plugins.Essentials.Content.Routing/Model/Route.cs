using System;
using System.ComponentModel.DataAnnotations.Schema;

using Microsoft.EntityFrameworkCore;

using VNLib.Plugins.Extensions.Data;

namespace VNLib.Plugins.Essentials.Content.Routing.Model
{
    [Index(nameof(Id), IsUnique = true)]
    internal class Route : DbModelBase
    {
        public override string Id { get; set; }
        public override DateTime Created { get; set; }
        public override DateTime LastModified { get; set; }

        public string Hostname { get; set; }
        public string MatchPath { get; set; }
        [Column("Privilage")]
        public long _privilage
        {
            get => (long)Privilage;
            set => Privilage = (ulong)value;
        }
        [NotMapped]
        public ulong Privilage { get; set; }

        public string Alternate { get; set; }
        public FpRoutine Routine { get; set; }       

        /// <summary>
        /// The processing arguments that match the route
        /// </summary>
        [NotMapped]
        public FileProcessArgs MatchArgs
        {
            get
            {
                return new FileProcessArgs()
                {
                    Alternate = this.Alternate,
                    Routine = (FpRoutine) Routine
                };
            }
        }
    }
}
