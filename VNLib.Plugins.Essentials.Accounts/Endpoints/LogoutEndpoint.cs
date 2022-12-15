/*
* Copyright (c) 2022 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: LogoutEndpoint.cs 
*
* LogoutEndpoint.cs is part of VNLib.Plugins.Essentials.Accounts which is part of the larger 
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

using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Essentials.Endpoints;

namespace VNLib.Plugins.Essentials.Accounts.Endpoints
{
    [ConfigurationName("logout_endpoint")]
    internal class LogoutEndpoint : ProtectedWebEndpoint
    {
        
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
