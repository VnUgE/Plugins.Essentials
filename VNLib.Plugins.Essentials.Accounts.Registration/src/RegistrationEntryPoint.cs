
using VNLib.Utils.Logging;

using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Routing;
using VNLib.Plugins.Essentials.Accounts.Registration.Endpoints;

namespace VNLib.Plugins.Essentials.Accounts.Registration
{
    public sealed class RegistrationEntryPoint : PluginBase
    {
        public override string PluginName => "Essentials.EmailRegistration";

        protected override void OnLoad()
        {
            try
            {
                //Route reg endpoint
                this.Route<RegistrationEntpoint>();
                
                Log.Information("Plugin loaded");
            }
            catch(KeyNotFoundException kne)
            {
                Log.Error("Missing required configuration variables: {ex}", kne.Message);
            }
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