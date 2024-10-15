/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: RpcCommandResult.cs 
*
* RpcCommandResult.cs is part of VNLib.Plugins.Essentials.Accounts which is part of the larger 
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

using System.Net;

using VNLib.Utils;

namespace VNLib.Plugins.Essentials.Accounts.AccountRpc
{
    /// <summary>
    /// The result of an rpc operation
    /// </summary>
    /// <param name="Status">
    /// A value that returns the status of the operation. 0 for successful operation. 
    /// A value > 0 if the operation failed.
    /// </param>
    /// <param name="Response">
    /// The response object to return to the client. This reference may be null 
    /// for any reason.
    /// </param>
    public readonly record struct RpcCommandResult(ERRNO Status, object? Response)
    {
        /// <summary>
        /// Closes the connection with the specified status code and optional response object
        /// </summary>
        /// <param name="code">The response code to return to the caller</param>
        /// <param name="response">The optional response object</param>
        /// <returns>The rpc command result structure configured with the correct error</returns>
        public static RpcCommandResult Error(HttpStatusCode code, object? response = null)
            => new((int)code, response);

        /// <summary>
        /// Closes the connection with the specified status code and optional response object
        /// </summary>
        /// <param name="response">The optional response object</param>
        /// <returns>The rpc command result structure configured with the correct error</returns>
        public static RpcCommandResult Okay(object? response = null)
            => new(0, response);
    }
}