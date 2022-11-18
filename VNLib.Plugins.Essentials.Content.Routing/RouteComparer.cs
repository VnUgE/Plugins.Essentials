using System.Collections.Generic;

using VNLib.Plugins.Essentials.Content.Routing.Model;

using static VNLib.Plugins.Essentials.Accounts.AccountManager;

namespace VNLib.Plugins.Essentials.Content.Routing
{
    /// <summary>
    /// Sorts routing rules based on closest match path/hostname routing along with privilage priority
    /// </summary>
    internal class RouteComparer : IComparer<Route>
    {
        //The idea is that hostnames without wildcards are exact, and hostnames with wildcards are "catch all"
        public int Compare(Route x, Route y)
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
                val = (x.Privilage & LEVEL_MSK) > (y.Privilage & LEVEL_MSK) ? 1 : -1;
            }
            //If both contain (or are) wildcards, then they are equal
            return val;
        }
    }
}
