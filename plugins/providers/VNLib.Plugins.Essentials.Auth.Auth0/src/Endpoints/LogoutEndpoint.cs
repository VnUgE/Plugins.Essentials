/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Auth.Auth0
* File: LogoutEndpoint.cs 
*
* LogoutEndpoint.cs is part of VNLib.Plugins.Essentials.Auth.Auth0 which is 
* part of the larger VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Auth.Auth0 is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Auth.Auth0 is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

using VNLib.Utils.IO;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Essentials.Accounts;
using VNLib.Plugins.Essentials.Endpoints;


namespace VNLib.Plugins.Essentials.Auth.Auth0.Endpoints
{
    [ConfigurationName(Auth0Portal.ConfigKey)]
    internal sealed class LogoutEndpoint : ProtectedWebEndpoint
    {
        private readonly IAsyncLazy<VnMemoryStream> ReturnUrl;

        public LogoutEndpoint(PluginBase plugin, IConfigScope config)
        {
            string returnToUrl = config.GetRequiredProperty("return_to_url", p => p.GetString()!);
            string logoutUrl = config.GetRequiredProperty("logout_url", p => p.GetString()!);
            string path = config.GetRequiredProperty("path", p => p.GetString()!);

            InitPathAndLog($"{path}/logout", plugin.Log);

            //Build the return url once the client id is available
            ReturnUrl = plugin.GetSecretAsync("auth0_client_id").ToLazy(sr =>
            {
                //The result we will send to users on logout so then can properly redirect their clients
                LogoutResult json = new()
                {
                    Url = $"{logoutUrl}?client_id={sr.Result.ToString()}&returnTo={returnToUrl}"
                };

                VnMemoryStream vms = new();
                JsonSerializer.Serialize(vms, json);
                return VnMemoryStream.CreateReadonly(vms);
            });
        }

        protected override VfReturnType Post(HttpEntity entity)
        {
            //Invalidate the login before redirecting the client
            entity.InvalidateLogin();

            return VirtualClose(
                entity, 
                HttpStatusCode.OK, 
                Net.Http.ContentType.Json,  
                ReturnUrl.Value.GetReadonlyShallowCopy()    //Return stream shallow copy to avoid alloc and copy
            );
        }

        sealed class LogoutResult
        {
            [JsonPropertyName("url")]
            public string? Url { get; set; }
        }
    }
}