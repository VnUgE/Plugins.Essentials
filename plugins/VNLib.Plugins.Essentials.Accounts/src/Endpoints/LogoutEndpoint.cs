/*
* Copyright (c) 2023 Vaughn Nugent
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

using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Essentials.Endpoints;

namespace VNLib.Plugins.Essentials.Accounts.Endpoints
{
    [ConfigurationName("logout_endpoint")]
    internal class LogoutEndpoint : UnprotectedWebEndpoint
    {
        
        public LogoutEndpoint(PluginBase pbase, IConfigScope config)
        {
            string? path = config["path"].GetString();
            InitPathAndLog(path, pbase.Log);
        }

        
        protected override VfReturnType Post(HttpEntity entity)
        {
            /*
             * If a connection is not properly authorized to modify the session
             * we can invalidate the client by detaching the session. This 
             * should cause the session to remain in tact but the client will
             * be detached.
             * 
             * This prevents attacks where connection with just a stolen session 
             * id can cause the client's session to be invalidated. 
             */
           
            if (entity.IsClientAuthorized(AuthorzationCheckLevel.Critical))
            {
                entity.InvalidateLogin();
            }
            else
            {
                //Detatch the session to cause client only invalidation
                entity.Session.Detach();
            }

            return VirtualOk(entity);
        }
    }
}
