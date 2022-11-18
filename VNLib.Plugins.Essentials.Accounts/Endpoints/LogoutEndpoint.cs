using System;
using System.Net;
using System.Text.Json;
using System.Collections.Generic;

using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Essentials.Endpoints;

namespace VNLib.Plugins.Essentials.Accounts.Endpoints
{
    [ConfigurationName("logout_endpoint")]
    internal class LogoutEndpoint : ProtectedWebEndpoint
    {        
        //Use default ep protection (most strict)
        
        ///<inheritdoc/>
        protected override ProtectionSettings EndpointProtectionSettings { get; } = new();

        
        public LogoutEndpoint(PluginBase pbase, IReadOnlyDictionary<string, JsonElement> config)
        {
            string? path = config["path"].GetString();
            InitPathAndLog(path, pbase.Log);
        }

        
        protected override VfReturnType Post(HttpEntity entity)
        {
            entity.InvalidateLogin();
            entity.CloseResponse(HttpStatusCode.OK);
            return VfReturnType.VirtualSkip;
        }
    }
}
