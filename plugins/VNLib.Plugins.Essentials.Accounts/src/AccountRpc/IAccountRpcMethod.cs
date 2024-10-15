/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: IAccountRpcMethod.cs 
*
* IAccountRpcMethod.cs is part of VNLib.Plugins.Essentials.Accounts which 
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

using System.Text.Json;
using System.Threading.Tasks;

namespace VNLib.Plugins.Essentials.Accounts.AccountRpc
{

    /// <summary>
    /// Represents a single rpc method that can be called by the user
    /// </summary>
    public interface IAccountRpcMethod
    {
        /// <summary>
        /// The name of this method users will request
        /// </summary>
        string MethodName { get; }

        /// <summary>
        /// The options required to call this method
        /// </summary>
        RpcMethodOptions Flags { get; }

        /// <summary>
        /// Called when the user makes a GET request to the login endpoint.
        /// All rpc controllers may return an object that will be serialized
        /// with the response.
        /// </summary>
        /// <param name="entity">The client entity making the request</param>
        /// <returns>A value task that resolves the object instance to return to the user</returns>
        ValueTask<object?> OnUserGetAsync(HttpEntity entity);

        /// <summary>
        /// Performs the desired operation for this method passing the original login message
        /// and the current request document
        /// </summary>
        /// <param name="entity">The client entity making the request</param>
        /// <param name="message">The original rpc control message received from the client</param>
        /// <param name="request">The request data object</param>
        /// <returns>The result of the operation.</returns>
        ValueTask<RpcCommandResult> InvokeAsync(HttpEntity entity, AccountJRpcRequest message, JsonElement request);
    }
}