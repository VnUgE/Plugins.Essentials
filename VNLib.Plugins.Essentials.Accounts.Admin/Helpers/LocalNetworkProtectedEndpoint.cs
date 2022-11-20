/*
* Copyright (c) 2022 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts.Admin
* File: LocalNetworkProtectedEndpoint.cs 
*
* LocalNetworkProtectedEndpoint.cs is part of VNLib.Plugins.Essentials.Accounts.Admin which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Accounts.Admin is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Accounts.Admin is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

using System;

using VNLib.Utils;
using VNLib.Plugins.Essentials.Endpoints;

namespace VNLib.Plugins.Essentials.Accounts.Admin.Helpers
{
    /// <summary>
    /// Provides an endpoint that provides optional protection against requests outside the local network
    /// </summary>
    internal abstract class LocalNetworkProtectedEndpoint : ProtectedWebEndpoint
    {
        private bool _localOnly;

        /// <summary>
        /// Specifies if requests outside of the local network are allowed.
        /// </summary>
        protected bool LocalOnly
        {
            get => _localOnly;
            set => _localOnly = value;
        }

        protected override ERRNO PreProccess(HttpEntity entity)
        {
            return (!_localOnly || entity.IsLocalConnection) && base.PreProccess(entity);
        }

    }
}
