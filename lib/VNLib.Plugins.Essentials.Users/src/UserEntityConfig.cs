/*
* Copyright (c) 2025 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Users
* File: UserEntityConfig.cs 
*
* UserEntityConfig.cs is part of VNLib.Plugins.Essentials.Users which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Users is free software: you can redistribute it and/or modify 
* it under the terms of the GNU General Public License as published
* by the Free Software Foundation, either version 2 of the License,
* or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Users is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
* General Public License for more details.
*
* You should have received a copy of the GNU General Public License 
* along with VNLib.Plugins.Essentials.Users. If not, see http://www.gnu.org/licenses/.
*/

using System.Threading;
using System.Threading.Tasks;

using VNLib.Plugins.Essentials.Users.Model;

namespace VNLib.Plugins.Essentials.Users
{

    internal delegate Task OnUserDelete(UserEntry userEntry, CancellationToken cancellationToken);

    internal delegate Task OnUserUpdate(UserEntry userEntry, CancellationToken cancellationToken);

    internal sealed class UserEntityConfig
    {
        internal required OnUserDelete OnUserDelete { get; init; }

        internal required OnUserUpdate OnUserUpdate { get; init; }

        internal required IUserFieldSerializer FieldSerializer { get; init; }

        internal required IUserObjectSerializer ObjectSerializer { get; init; }
    }
}