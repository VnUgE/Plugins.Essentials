/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: KeepAliveEndpoint.cs 
*
* KeepAliveEndpoint.cs is part of VNLib.Plugins.Essentials.Accounts which is part of the larger 
* VNLib collection of libraries and utilities.
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

using System;

using VNLib.Utils.Extensions;
using VNLib.Plugins.Essentials.Endpoints;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Routing;


namespace VNLib.Plugins.Essentials.Accounts.Endpoints
{
    [EndpointPath("{{path}}")]
    [EndpointLogName("Heartbeat")]
    [ConfigurationName("keepalive_endpoint")]
    internal sealed class KeepAliveEndpoint(PluginBase plugin, IConfigScope config) : ProtectedWebEndpoint
    {
        private readonly TimeSpan tokenRegenTime = config.GetRequiredProperty(
            property: "token_refresh_sec", 
            static p => p.GetTimeSpan(TimeParseType.Seconds)
        );

        protected override VfReturnType Get(HttpEntity entity) => VirtualOk(entity);

        //Allow post to update user's credentials
        protected override VfReturnType Post(HttpEntity entity)
        {
            //See if its time to regenreate the client's auth status
            if (entity.Session.Created.Add(tokenRegenTime) < entity.RequestedTimeUtc)
            {
                WebMessage webm = new()
                {
                    Success = true
                };

                //reauthorize the client
                entity.ReAuthorizeClient(webm);
              
                //Send the update message to the client
                return VirtualOk(entity, webm);
            }

            //Return okay
            return VirtualOk(entity);
        }
    }
}