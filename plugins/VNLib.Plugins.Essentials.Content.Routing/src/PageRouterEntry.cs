/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Content.Routing
* File: PageRouterEntry.cs 
*
* PageRouterEntry.cs is part of VNLib.Plugins.Essentials.Content.Routing which is part of the larger 
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
using System.Threading.Tasks;
using System.ComponentModel.Design;

using VNLib.Utils.Logging;
using VNLib.Plugins.Attributes;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Sql;
using VNLib.Plugins.Essentials.Content.Routing.Model;

namespace VNLib.Plugins.Essentials.Content.Routing
{
    public sealed class PageRouterEntry : PluginBase
    {
        public override string PluginName => "Essentials.Router";

        private Router PageRouter;

        [ServiceConfigurator]
        public void ConfigureServices(IServiceContainer services)
        {
            //Deploy the page router to the host
            services.AddService(typeof(IPageRouter), PageRouter);
        }

        protected override void OnLoad()
        {
            //Init router
            PageRouter = this.GetOrCreateSingleton<Router>();

            //Schedule the db creation
            _ = this.ObserveWork(OnDbCreationAsync, 500);

            Log.Information("Plugin loaded");
        }

        protected override void OnUnLoad()
        {
            Log.Information("Plugin unloaded");
        }

        protected override void ProcessHostCommand(string cmd)
        {
            if(cmd.Contains("reset", StringComparison.OrdinalIgnoreCase))
            {
                PageRouter?.ResetRoutes();
                Log.Information("Routing table reset");
            }
        }

        private async Task OnDbCreationAsync()
        {
            //Create the router
            await this.EnsureDbCreatedAsync<RoutingContext>(null);
        }
    }
}
