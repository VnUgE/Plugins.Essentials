/*
* Copyright (c) 2022 Vaughn Nugent
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
using System.Net;
using System.Text.Json;
using System.Collections.Generic;

using VNLib.Utils.Extensions;
using VNLib.Plugins.Essentials.Endpoints;
using VNLib.Plugins.Essentials.Extensions;
using VNLib.Plugins.Extensions.Loading;


namespace VNLib.Plugins.Essentials.Accounts.Endpoints
{
    [ConfigurationName("keepalive_endpoint")]
    internal sealed class KeepAliveEndpoint : ProtectedWebEndpoint
    {
        readonly TimeSpan tokenRegenTime;

        /*
         * Endpoint does not use a log, so IniPathAndLog is never called
         * and path verification happens verbosly 
         */
        public KeepAliveEndpoint(PluginBase pbase, IReadOnlyDictionary<string, JsonElement> config)
        {
            string? path = config["path"].GetString();

            tokenRegenTime = config["token_refresh_sec"].GetTimeSpan(TimeParseType.Seconds);

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
            //Get the last token update
            DateTimeOffset lastTokenUpdate = entity.Session.LastTokenUpgrade();

            //See if its expired
            if (lastTokenUpdate.Add(tokenRegenTime) < entity.RequestedTimeUtc)
            {
                //if so updaet token
                WebMessage webm = new()
                {
                    Token = entity.RegenerateClientToken(),
                    Success = true
                };
                
                //Send the update message to the client
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }

            //Return okay
            entity.CloseResponse(HttpStatusCode.OK);
            return VfReturnType.VirtualSkip;
        }
    }
}