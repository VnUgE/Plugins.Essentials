/*
* Copyright (c) 2022 Vaughn Nugent
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
using System.Collections.Generic;

using VNLib.Utils.Logging;

namespace VNLib.Plugins.Essentials.Content.Routing
{
    public sealed class PageRouterEntry : PluginBase, IPageRouter
    {
        public override string PluginName => "Essentials.Router";

        private Router PageRouter;
        public ValueTask<FileProcessArgs> RouteAsync(HttpEntity entity) => PageRouter.RouteAsync(entity);

        protected override void OnLoad()
        {
            try
            {
                //Init router
                PageRouter = new(this);
                Log.Information("Plugin loaded");
            }
            catch (KeyNotFoundException knf)
            {
                Log.Error("Plugin failed to load, missing required configuration variables {err}", knf.Message);
            }
        }

        protected override void OnUnLoad()
        {
            Log.Information("Plugin unloaded");
        }

        protected override void ProcessHostCommand(string cmd)
        {
            if(cmd.Contains("reset"))
            {
                PageRouter?.ResetRoutes();
                Log.Information("Routing table reset");
            }
        }
    }
}
