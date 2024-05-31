﻿/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: MfaEncodedData.cs 
*
* MfaEncodedData.cs is part of VNLib.Plugins.Essentials.Accounts which is part of the larger 
* VNLib collection of libraries and utilities.
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

using System;
using System.Text.Json;

using VNLib.Utils;
using VNLib.Utils.IO;
using VNLib.Utils.Memory;


namespace VNLib.Plugins.Essentials.Accounts.MFA
{
    internal static class UserEnocdedData 
    {
        /// <summary>
        /// Recovers encoded items from the user's account object
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="store">The data store to read encoded data from</param>
        /// <param name="index">The property index in the user fields to recover the objects from</param>
        /// <returns>The encoded properties from the desired user index</returns>
        public static T? Decode<T>(IIndexable<string, string> store, string index) where T : class
        {
            ArgumentNullException.ThrowIfNull(store);
            ArgumentException.ThrowIfNullOrWhiteSpace(index);

            string? encodedData = store[index];

            if (string.IsNullOrWhiteSpace(encodedData))
            {
                return null;
            }

            //Output buffer will always be smaller than actual input data due to base64 encoding
            using UnsafeMemoryHandle<byte> binBuffer = MemoryUtil.UnsafeAllocNearestPage(encodedData.Length, true);
           
            ERRNO bytes = VnEncoding.Base64UrlDecode(encodedData, binBuffer.Span);

            if (!bytes)
            {
                return null;
            }

            //Deserialize the objects directly from binary data
            return JsonSerializer.Deserialize<T>(
                utf8Json: binBuffer.AsSpan(0, bytes), 
                options: Statics.SR_OPTIONS
            );
        }

        /// <summary>
        /// Writes a set of items to the user's account object, encoded in base64
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="store"></param>
        /// <param name="index">The store index to write the encoded string data to</param>
        /// <param name="instance">The object instance to encode and store</param>
        public static void Encode<T>(IIndexable<string, string> store, string index, T? instance) where T : class
        {
            ArgumentNullException.ThrowIfNull(store);
            ArgumentException.ThrowIfNullOrWhiteSpace(index);

            if (instance == null)
            {
                store[index] = null!;
                return;
            }

            //Use a memory stream to serialize the items safely
            using VnMemoryStream ms = new(MemoryUtil.Shared, 1024, false);
            
            JsonSerializer.Serialize(ms, instance, Statics.SR_OPTIONS);

            store[index] = VnEncoding.ToBase64UrlSafeString(ms.AsSpan(), false);
        }
    }
}
