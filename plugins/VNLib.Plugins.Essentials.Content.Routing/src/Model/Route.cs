/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Content.Routing
* File: Route.cs 
*
* Route.cs is part of VNLib.Plugins.Essentials.Content.Routing which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Content.Routing is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Content.Routing is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

using Microsoft.EntityFrameworkCore;

using VNLib.Plugins.Extensions.Data;

namespace VNLib.Plugins.Essentials.Content.Routing.Model
{
    [Index(nameof(Id), IsUnique = true)]
    internal class Route : DbModelBase
    {
        public const FpRoutine RewriteRoutine = (FpRoutine)50;

        [Key]
        public override string Id { get; set; }
        public override DateTime Created { get; set; }
        public override DateTime LastModified { get; set; }

        public string Hostname { get; set; }

        public string MatchPath { get; set; }

        [Column("Privilege")]
        public long _privilege
        {
            get => (long)Privilege;
            set => Privilege = (ulong)value;
        }

        [NotMapped]
        public ulong Privilege { get; set; }

        public string? Alternate { get; set; } = string.Empty;

        public FpRoutine Routine { get; set; }

        public string? RewriteSearch { get; set; }

        /// <summary>
        /// Creates the <see cref="FileProcessArgs"/> to return to the processor 
        /// for the current rule, which may include rewriting the url.
        /// </summary>
        /// <param name="entity">The connection to get the args for</param>
        /// <returns>The <see cref="FileProcessArgs"/> for the connection</returns>
        public FileProcessArgs GetArgs(HttpEntity entity)
        {
            //Check for rewrite routine
            if (Routine == RewriteRoutine)
            {
                //Rewrite the request url and return the args, processor will clean and parse url
                string rewritten = entity.Server.Path.Replace(RewriteSearch!, Alternate!, StringComparison.OrdinalIgnoreCase);

                //Set to rewrite args
                return new FileProcessArgs(FpRoutine.ServeOther, rewritten);
            }
            else
            {
                return new FileProcessArgs(Routine, Alternate!);
            }
        }
    }
}
