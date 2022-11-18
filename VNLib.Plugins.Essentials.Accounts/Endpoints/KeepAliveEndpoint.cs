using System;
using System.Net;
using System.Text.Json;
using System.Collections.Generic;

using VNLib.Plugins.Essentials.Endpoints;
using VNLib.Plugins.Extensions.Loading;

namespace VNLib.Plugins.Essentials.Accounts.Endpoints
{
    [ConfigurationName("keepalive_endpoint")]
    internal sealed class KeepAliveEndpoint : ProtectedWebEndpoint
    {
        /*
         * Endpoint does not use a log, so IniPathAndLog is never called
         * and path verification happens verbosly 
         */
        public KeepAliveEndpoint(PluginBase pbase, IReadOnlyDictionary<string, JsonElement> config)
        {
            string? path = config["path"].GetString();

            InitPathAndLog(path, pbase.Log);
        }

        protected override VfReturnType Get(HttpEntity entity)
        {
            //Return okay
            entity.CloseResponse(HttpStatusCode.OK);
            return VfReturnType.VirtualSkip;
        }

        //Allow post to update user's credentials
        protected override VfReturnType Post(HttpEntity entity)
        {
            //Return okay
            entity.CloseResponse(HttpStatusCode.OK);
            return VfReturnType.VirtualSkip;
        }
    }
}