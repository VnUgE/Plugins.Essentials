/*
* Copyright (c) 2022 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts.Admin
* File: AccountAdminEntry.cs 
*
* AccountAdminEntry.cs is part of VNLib.Plugins.Essentials.Accounts.Admin which is part of the larger 
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
using System.Text.Json;
using System.Runtime.CompilerServices;

using VNLib.Utils.Logging;
using VNLib.Plugins.Essentials.Sessions;

namespace VNLib.Plugins.Essentials.Accounts.Admin
{

    internal static class Constants
    {
        public const ushort ADMIN_GROUP_ID = 0x1fff;
        [Flags]
        enum AdminLevelMask
        {
            
        }
        /// <summary>
        /// Determines if the current session belongs to an admin account
        /// </summary>
        /// <param name="session"></param>
        /// <returns>True if the current user has administrator permissions</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool IsAdmin(this in SessionInfo session) => session.HasGroup(ADMIN_GROUP_ID);

        /// <summary>
        /// Gets the plugin config local-only flag
        /// </summary>
        /// <param name="plugin"></param>
        /// <returns>True if the config demands all requests happen on the local network only</returns>
        public static bool LocalOnlyEnabled(this PluginBase plugin)
        {
            return plugin.PluginConfig.TryGetProperty("local_only", out JsonElement el) && el.GetBoolean();
        }
    }
    
    public sealed class AccountAdminEntry : PluginBase
    {
        public override string PluginName => "Essentials.Admin";

        protected override void OnLoad()
        {
            try
            {
               
            }
            catch (KeyNotFoundException knf)
            {
                Log.Error("Missing required account configuration variables {mess}", knf.Message);
                return;
            }
            //Write loaded to log
            Log.Information("Plugin loaded");
        }

        protected override void OnUnLoad()
        {
            Log.Information("Plugin unloaded");
        }

        protected override void ProcessHostCommand(string cmd)
        {
            Log.Debug(cmd);
        }
    }
}