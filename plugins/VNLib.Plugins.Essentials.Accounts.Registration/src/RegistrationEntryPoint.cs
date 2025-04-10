﻿/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts.Registration
* File: RegistrationEntryPoint.cs 
*
* RegistrationEntryPoint.cs is part of VNLib.Plugins.Essentials.Accounts.Registration which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Accounts.Registration is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Accounts.Registration is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

using System.Threading.Tasks;

using VNLib.Utils.Logging;

using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Sql;
using VNLib.Plugins.Extensions.Loading.Routing;
using VNLib.Plugins.Essentials.Accounts.Registration.Endpoints;

namespace VNLib.Plugins.Essentials.Accounts.Registration
{
    public sealed class RegistrationEntryPoint : PluginBase
    {
        public override string PluginName => "Essentials.EmailRegistration";

        protected override void OnLoad()
        {
            //Route reg endpoint
            this.Route<RegistrationEntpoint>();

            //Schedule creating database tables
            _ = this.ObserveWork(CreateDatabaseTables, 1000);

            Log.Information("Plugin loaded");
        }

        private async Task CreateDatabaseTables()
        {
            //Ensure the database is created
            await this.EnsureDbCreatedAsync<RegistrationContext>(this);
        }

        protected override void OnUnLoad()
        {
            Log.Information("Plugin unloaded");
        }

        protected override void ProcessHostCommand(string cmd)
        {
            if (!this.IsDebug())
            {
                return;
            }
        }
    }
}