﻿/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: IAccountRpcController.cs 
*
* IAccountRpcController.cs is part of VNLib.Plugins.Essentials.Accounts which 
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

namespace VNLib.Plugins.Essentials.Accounts.AccountRpc
{
    /// <summary>
    /// Represents a controller that handles rpc methods for the account
    /// </summary>
    public interface IAccountRpcController
    {
        /// <summary>
        /// Gets all rpc methods for this controller
        /// </summary>
        /// <returns>The methods that will be handled by the rpc endpoint</returns>
        IAccountRpcMethod[] GetMethods();
    }
}