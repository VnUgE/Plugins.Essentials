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

namespace VNLib.Plugins.Essentials.Auth.Social.Controllers
{
    public interface ISocialOauthMethod
    {
        /// <summary>
        /// The unique name of the method as requested by clients
        /// </summary>
        string MethodName { get; }

        ValueTask<object?> OnGetInfo(HttpEntity entity);

        ValueTask<SocialUpgradeResult> OnUpgradeAsync(SocialMethodState state, JsonElement request);

        ValueTask<object?> OnAuthenticateAsync(SocialMethodState state, IClientSecInfo secInfo, JsonElement args, JsonElement stateData);

        ValueTask<object?> OnLogoutAsync(SocialMethodState state, JsonElement request);
    }
}
