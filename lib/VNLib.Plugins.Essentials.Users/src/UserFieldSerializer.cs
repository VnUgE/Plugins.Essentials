/*
* Copyright (c) 2025 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Users
* File: UserFieldSerializer.cs 
*
* UserFieldSerializer.cs is part of VNLib.Plugins.Essentials.Users which is part of the larger 
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

using System;
using System.Text.Json;

using VNLib.Plugins.Essentials.Users.Model;
using static VNLib.Plugins.Essentials.Statics;

namespace VNLib.Plugins.Essentials.Users
{
    internal class UserFieldSerializer : IUserFieldSerializer
    {
        private readonly JsonSerializerOptions _jsonOptions = SR_OPTIONS;

        ///<inheritdoc/>
        public UserExtendedFields? GetFields(UserEntry userEntry)
        {
            if (userEntry.UserData is null || userEntry.UserData.Length == 0)
            {
                return null;
            }

            try
            {
                return JsonSerializer.Deserialize<UserExtendedFields>(userEntry.UserData, _jsonOptions);
            }
            catch (JsonException)
            {
                /*
                 * If a json related exception is thrown, it means that the data 
                 * is not in the expected format or is corrupted. If null is returned
                 * the user data will be reset to an empty object
                 */

                return null;
            }
        }

        ///<inheritdoc/>
        public void StoreFields(UserEntry userEntry, UserExtendedFields fields)
        {
            ArgumentNullException.ThrowIfNull(fields);
            ArgumentNullException.ThrowIfNull(userEntry);

            //Serialize the fields to json and store them in the user entry
            userEntry.UserData = JsonSerializer.SerializeToUtf8Bytes(fields, _jsonOptions);
        }
    }
}