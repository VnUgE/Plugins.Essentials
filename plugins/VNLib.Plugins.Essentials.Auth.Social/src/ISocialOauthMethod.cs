/*
* Copyright (c) 2025 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Auth.Social
* File: ISocialOauthMethod.cs 
*
* ISocialOauthMethod.cs is part of VNLib.Plugins.Essentials.Auth.Social which is 
* part of the larger VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Auth.Social is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Auth.Social is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

using VNLib.Plugins.Essentials.Accounts;

namespace VNLib.Plugins.Essentials.Auth.Social
{

    /// <summary>
    /// Represents a method for authenticating a user using a social oauth system, which will by exported
    /// by a <see cref="ISocialOauthController"/>
    /// </summary>
    public interface ISocialOauthMethod
    {
        /// <summary>
        /// The unique name of the method as requested by clients
        /// </summary>
        string MethodName { get; }

        /// <summary>
        /// Invoked when a user requests a get method on the account controller. It returns any 
        /// method-specific json-serilizable data that should be returned to the client under 
        /// this method's data object.
        /// </summary>
        /// <param name="entity">The connection initating the request</param>
        /// <returns>A valuetask that returns an optional object to the</returns>
        ValueTask<object?> OnGetInfo(HttpEntity entity);

        /// <summary>
        /// Invoked when the user requests a connection upgrade using this social oauth method.
        /// Most client/connection security checks are handled at the controller level.
        /// </summary>
        /// <param name="state">
        /// A state object for data and functions associated with the social oauth system
        /// </param>
        /// <param name="args">The function argument parameters for this method</param>
        /// <returns>A value task that returns the result of the connection upgrade</returns>
        ValueTask<SocialUpgradeResult> OnUpgradeAsync(SocialMethodState state, JsonElement args);

        /// <summary>
        /// Invoked when the user wishes to continue the authentication process after the
        /// connection upgrade has been completed. (redirected back to this server)
        /// </summary>
        /// <param name="state">
        /// A state object for data and functions associated with the social oauth system
        /// </param>
        /// <param name="secInfo">The connection's security info captured during the upgrade procedure</param>
        /// <param name="args">The method arguments passed by the client</param>
        /// <param name="stateData">The state data stored from the most recent successful upgrade result</param>
        /// <returns>A value task that returns an arbitraty object back to the user as a result of the operation</returns>
        ValueTask<object?> OnAuthenticateAsync(SocialMethodState state, IClientSecInfo secInfo, JsonElement args, JsonElement stateData);

        /// <summary>
        /// Invoked when the user requests to log out of the social oauth system but previously logged
        /// in using this method.
        /// </summary>
        /// <param name="state">
        /// A state object for data and functions associated with the social oauth system
        /// </param>
        /// <param name="args">The method arguments passed by the client</param>
        /// <returns>A value task that returns an arbitraty object back to the user as a result of the operation</returns>
        ValueTask<object?> OnLogoutAsync(SocialMethodState state, JsonElement args);
    }
}
