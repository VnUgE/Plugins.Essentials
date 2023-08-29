/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Content.Routing
* File: RouteComparer.cs 
*
* RouteComparer.cs is part of VNLib.Plugins.Essentials.Content.Routing which is part of the larger 
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

using System.Collections.Generic;

using VNLib.Plugins.Essentials.Content.Routing.Model;

using static VNLib.Plugins.Essentials.Accounts.AccountUtil;

namespace VNLib.Plugins.Essentials.Content.Routing
{
    /// <summary>
    /// Sorts routing rules based on closest match path/hostname routing along with privilage priority
    /// </summary>
    internal sealed class RouteComparer : IComparer<Route>
    {
        //The idea is that hostnames without wildcards are exact, and hostnames with wildcards are "catch all"
        public int Compare(Route? x, Route? y)
        {
            int val = 0;
            //If x contains a wildcard in the hostname, then it is less than y
            if (x.Hostname.Contains('*'))
            {
                val--;
            }
            //If y containts a wildcard, then y is less than x
            if (y.Hostname.Contains('*'))
            {
                val++;
            }
            //If there was no wildcard, check paths
            if (val == 0)
            {
                //If x containts a wildcard in the path, then x is less than y
                if (x.MatchPath.Contains('*'))
                {
                    val--;
                }
                //If y containts a wildcard in the path, then y is less than x
                if (y.MatchPath.Contains('*'))
                {
                    val++;

                }
            }
            //If hostnames and paths are stil equal, check privilage level
            if (val == 0)
            {
                //Higher privilage routine is greater than lower privilage
                val = (x.Privilege & LEVEL_MSK) > (y.Privilege & LEVEL_MSK) ? 1 : -1;
            }
            //If both contain (or are) wildcards, then they are equal
            return val;
        }
    }
}
