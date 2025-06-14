/*
* Copyright (c) 2025 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Users
* File: UserObjectSerializer.cs 
*
* UserObjectSerializer.cs is part of VNLib.Plugins.Essentials.Users which is part of the larger 
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

using System.Text.Json;

using static VNLib.Plugins.Essentials.Statics;

namespace VNLib.Plugins.Essentials.Users
{
    internal sealed class UserObjectSerializer : IUserObjectSerializer
    {
        private readonly JsonSerializerOptions _jsonOptions = SR_OPTIONS;


        ///<inheritdoc/>
        public T? Deserialize<T>(string json)
        {
            return JsonSerializer.Deserialize<T>(json, _jsonOptions);
        }

        ///<inheritdoc/>
        public string? Serialize<T>(T value)
        {
            return value is not null
                ? JsonSerializer.Serialize(value, _jsonOptions) 
                : null;
        }
    }
}