/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Auth.Social
* File: SocialAuthEntry.cs 
*
* SocialAuthEntry.cs is part of VNLib.Plugins.Essentials.Auth.Social which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Auth.Social is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Auth.Social is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

using System;
using System.Linq;
using System.Text.Json;
using System.Collections.Generic;

using VNLib.Utils.Logging;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Routing;


namespace VNLib.Plugins.Essentials.Auth.Social
{

    public sealed class SocialAuthEntry : PluginBase
    {
        const string ProviderConfigKey = "providers";

        ///<inheritdoc/>
        public override string PluginName => "Auth.Socal";

        ///<inheritdoc/>
        protected override void OnLoad()
        {
            Log.Information("Loading social authentication providers");

            //Get provider array
            if(PluginConfig.TryGetProperty(ProviderConfigKey, out JsonElement providerArray))
            {
                //Get dll file names
                string[] providerDlls = providerArray.EnumerateArray()
                    .Select(e => e.GetString()!)
                    .ToArray();
                
                List<SocialOAuthPortal> portals = new();
                
                /*
                 * Using the loading library to create the exported services
                 * which are IOAuthProvider implementations
                 */
                foreach (string dll in providerDlls)
                {
                    //Load the dll
                    IOAuthProvider provider = this.CreateServiceExternal<IOAuthProvider>(dll);
                    
                    //Capture all portals
                    portals.AddRange(provider.GetPortals());

                    Log.Information($"Loaded OAuth method {provider.GetType().Name}");
                }

                //Define portals endpoint and set portals
                PortalsEndpoint p = this.Route<PortalsEndpoint>();
                p.SetPortals(portals);
            }
            else
            {
                Log.Warn("No providers array defined in config");
            }
        }

        ///<inheritdoc/>
        protected override void OnUnLoad()
        {
            Log.Information("Plugin unloaded");
        }

        ///<inheritdoc/>
        protected override void ProcessHostCommand(string cmd)
        {
            throw new NotImplementedException();
        }

      
    }
}