/*
* Copyright (c) 2025 Vaughn Nugent
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

using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Configuration;

namespace VNLib.Plugins.Essentials.Content.Routing.Model
{
    internal sealed class Route : IOnConfigValidation
    {        
        public required ProcessRoutine Routine { get; init; }
       
        public ulong Privilege { get; init; } = 0;
       
        public required string Hostname { get; init; }
       
        public required string MatchPath { get; init; } = string.Empty;

        public string? RewriteSearch { get; init; }
      
        public string? Alternate { get; init; }
      
        public string? Replace { get; init; }

        /// <summary>
        /// Creates the <see cref="FileProcessArgs"/> to return to the processor 
        /// for the current rule, which may include rewriting the url.
        /// </summary>
        /// <param name="entity">The connection to get the args for</param>
        /// <returns>The <see cref="FileProcessArgs"/> for the connection</returns>
        public FileProcessArgs GetArgs(HttpEntity entity)
        {
            //Check for rewrite routine
            if (Routine == ProcessRoutine.Rewrite)
            {
                //Rewrite the request url and return the args, processor will clean and parse url
                string rewritten = entity.Server.Path.Replace(RewriteSearch!, Replace!, StringComparison.OrdinalIgnoreCase);

                //Set to rewrite args
                return new FileProcessArgs(FpRoutine.ServeOther, rewritten);
            }
            else
            {
                return new FileProcessArgs((FpRoutine) Routine, Alternate!);
            }
        }

        ///<inheritdoc/>
        public void OnValidate()
        {
            Validate.NotNull(Hostname, "Hostname cannot be null or empty in route element");            

            switch (Routine)
            {
                case ProcessRoutine.Redirect:
                    Validate.NotNull(Alternate, "Alternate cannot be null or empty in route element for redirect routine");
                    Validate.NotNull(MatchPath, "Match path cannot be null or empty in route element");
                    break;

                case ProcessRoutine.ServeOther:
                    Validate.NotNull(Alternate, "Alternate cannot be null or empty in route element for serve other routine");
                    Validate.NotNull(MatchPath, "Match path cannot be null or empty in route element");
                    break;

                case ProcessRoutine.ServeOtherFQ:
                    Validate.NotNull(Alternate, "Alternate cannot be null or empty in route element for serve other FQ routine");
                    Validate.NotNull(MatchPath, "Match path cannot be null or empty in route element");
                    break;

                case ProcessRoutine.Rewrite:
                    Validate.NotNull(RewriteSearch, "Rewrite search cannot be null or empty in route element for rewrite routine");
                    Validate.NotNull(Replace, "Replace cannot be null or empty in route element for rewrite routine");

                    Validate.Assert(MatchPath != null, "You must not assign a null value to the 'path' paramter in a rewrite routine");
                    break;
            }                  
        }
    }
}
