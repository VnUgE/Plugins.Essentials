/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts.AppData
* File: AppDataEntry.cs 
*
* AppDataEntry.cs is part of VNLib.Plugins.Essentials.Accounts.AppData which 
* is part of the larger VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Accounts is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Accounts is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

using VNLib.Utils.Logging;
using VNLib.Plugins.Extensions.Loading.Routing;

using VNLib.Plugins.Essentials.Accounts.AppData.Endpoints;

namespace VNLib.Plugins.Essentials.Accounts.AppData
{
    public sealed class AppDataEntry : PluginBase
    {
        ///<inheritdoc/>
        public override string PluginName => "Essentials.AppData";

        ///<inheritdoc/>
        protected override void OnLoad()
        {
            this.Route<WebEndpoint>();
            Log.Information("Plugin loaded");
        }

        ///<inheritdoc/>
        protected override void OnUnLoad()
        {
            Log.Information("Plugin unloaded");
        }

        ///<inheritdoc/>
        protected override void ProcessHostCommand(string cmd)
        { }
    }
}
