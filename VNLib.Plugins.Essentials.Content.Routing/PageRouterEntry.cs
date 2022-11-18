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
