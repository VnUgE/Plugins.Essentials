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

using VNLib.Hashing.IdentityUtility;
using VNLib.Plugins.Essentials.Users;


namespace VNLib.Plugins.Essentials.Accounts.MFA
{
    internal interface IMfaProcessor
    {
        MFAType Type { get; }

        bool MethodEnabledForUser(IUser user);

        void ExtendUpgradePayload(in JwtPayload message, IUser user);

        bool VerifyResponse(MfaChallenge upgrade, IUser user, JsonDocument result);
    }
}