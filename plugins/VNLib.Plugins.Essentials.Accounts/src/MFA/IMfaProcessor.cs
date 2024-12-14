/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: IMfaProcessor.cs 
*
* IMfaProcessor.cs is part of VNLib.Plugins.Essentials.Accounts which is 
* part of the larger VNLib collection of libraries and utilities.
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

using VNLib.Hashing.IdentityUtility;
using VNLib.Plugins.Essentials.Users;


namespace VNLib.Plugins.Essentials.Accounts.MFA
{
    /// <summary>
    /// Represents a multi-factor authentication processor that can be used to
    /// authenticate a user against a specific MFA method.
    /// </summary>
    public interface IMfaProcessor
    {
        /// <summary>
        /// The processor type identifier
        /// </summary>
        string Type { get; }

        /// <summary>
        /// Determines if this processor is active for the specified user
        /// </summary>
        /// <param name="user">The user to check enabled method for</param>
        /// <returns>A value that indicates this processor is active for the user, false otherwise</returns>
        bool MethodEnabledForUser(IUser user);

        /// <summary>
        /// Determines if this processor is armed for the specified user. This
        /// means this method will be used to guard the user's account.
        /// </summary>
        /// <param name="user">The user to check enabled method for</param>
        /// <returns>A value that indicates this processor is armed for the user, false otherwise</returns>
        bool ArmedForUser(IUser user);

        /// <summary>
        /// Extends the upgrade payload with information specific to this processor 
        /// which will be signed and returned during the verification process. This 
        /// data may be used by the client to determine the type of MFA to use.
        /// </summary>
        /// <param name="message">The payload message to add data to</param>
        /// <param name="user">The user instance this upgrade is for</param>
        void ExtendUpgradePayload(in JwtPayload message, IUser user);

        /// <summary>
        /// Called when this processor is selected to authenticate a user against 
        /// it's mfa data. If this method returns true, this user's session will
        /// be authorized and the user will be logged in.
        /// </summary>
        /// <param name="user">The user account wishing to authenticate</param>
        /// <param name="request">The request message data the client submitted to </param>
        /// <returns>True if the user successfully logged-in, false otherwise</returns>
        bool VerifyResponse(IUser user, JsonElement request);

        /// <summary>
        /// Called when the client requests data for data to be mutated or displayed. May return
        /// any specialized data for the desired processor, it will be serialized into json.
        /// </summary>
        /// <param name="entity">The request entity issuing this action</param>
        /// <param name="request">The entire request entity json message</param>
        /// <param name="user">The user object matching the user making this request</param>
        /// <returns>A value task that resolves the object to serialize and return to the user</returns>
        ValueTask<object?> OnHandleMessageAsync(HttpEntity entity, JsonElement request, IUser user);

        /// <summary>
        /// Called when the client requests data for this processor to be displayed. May return 
        /// any specialized data for the desired processor, it will be serialized into json.
        /// </summary>
        /// <param name="entity">The request entity asking for data</param>
        /// <param name="user">The user entity requesting data against</param>
        /// <returns>A value task that resolves the object to serialize and return to the user</returns>
        ValueTask<object?> OnUserGetAsync(HttpEntity entity, IUser user);
    }
}