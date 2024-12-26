/*
* Copyright (c) 2022 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Oauth
* File: ITokenManager.cs 
*
* ITokenManager.cs is part of VNLib.Plugins.Essentials.Oauth which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Oauth is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Oauth is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace VNLib.Plugins.Essentials.Oauth.Tokens
{
    /// <summary>
    /// Provides token creation and revocation
    /// </summary>
    public interface ITokenManager
    {
        /// <summary>
        /// Revokes a colleciton of toke
        /// </summary>
        /// <param name="tokens">A collection of tokens to revoke</param>
        /// <param name="cancellation">A token to cancel the operation</param>
        /// <returns>A task that completes when the tokens have been revoked</returns>
        Task RevokeTokensAsync(IReadOnlyCollection<string> tokens, CancellationToken cancellation = default);
        /// <summary>
        /// Attempts to revoke tokens that belong to a specified application 
        /// </summary>
        /// <param name="appId">The application to revoke tokens for</param>
        /// <param name="cancellation">A token to cancel the operation</param>
        /// <returns>A task that completes when the work is complete</returns>
        Task RevokeTokensForAppAsync(string appId, CancellationToken cancellation = default);
    }
}