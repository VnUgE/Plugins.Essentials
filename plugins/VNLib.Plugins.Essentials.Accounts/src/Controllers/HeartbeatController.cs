/*
* Copyright (c) 2025 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: HeartbeatController.cs 
*
* HeartbeatController.cs is part of VNLib.Plugins.Essentials.Accounts which 
* is part of the larger VNLib collection of libraries and utilities.
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
using System.Text.Json;
using System.Threading.Tasks;

using VNLib.Utils.Extensions;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Essentials.Accounts.AccountRpc;

namespace VNLib.Plugins.Essentials.Accounts.Controllers
{
    [ConfigurationName("login")]
    internal sealed class HeartbeatController(PluginBase plugin, IConfigScope config) : IAccountRpcController
    {
        private readonly TimeSpan tokenRegenTime = config.GetRequiredProperty(
            property: "token_refresh_sec",
            static p => p.GetTimeSpan(TimeParseType.Seconds)
        );

        ///<inheritdoc/>
        public IAccountRpcMethod[] GetMethods()
        {
            return [new HeartbeatMethod(tokenRegenTime)];
        }

        private sealed class HeartbeatMethod(TimeSpan tokenRegenTime) : IAccountRpcMethod
        {
            ///<inheritdoc/>
            public string MethodName => "heartbeat";

            ///<inheritdoc/>
            public RpcMethodOptions Flags => RpcMethodOptions.AuthRequired;

            ///<inheritdoc/>
            public ValueTask<object?> OnUserGetAsync(HttpEntity entity)
            {
                /*
                 * Quick and dirty check if the user is logged in. Its not critical
                 * for sending some quick info
                 */
                if (entity.Session.UserID.Length > 0)
                {
                    return ValueTask.FromResult<object?>(new
                    {
                        type            = "heartbeat",
                        regen_seconds   = (int)tokenRegenTime.TotalSeconds
                    });
                }

                return default;
            }

            ///<inheritdoc/>
            public ValueTask<RpcCommandResult> InvokeAsync(HttpEntity entity, AccountJRpcRequest _, JsonElement args)
            {
                //See if its time to regenreate the client's auth status
                if (entity.Session.Created.Add(tokenRegenTime) < entity.RequestedTimeUtc)
                {
                    WebMessage webm = new() { Success = true };

                    //reauthorize the client
                    entity.ReAuthorizeClient(webm);

                    //Send the update message to the client
                    return ValueTask.FromResult(RpcCommandResult.Okay(webm));
                }

                return ValueTask.FromResult(RpcCommandResult.Okay());
            }
        }
    }
}