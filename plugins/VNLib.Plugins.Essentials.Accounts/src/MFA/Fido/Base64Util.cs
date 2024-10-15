/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: Base64Util.cs 
*
* Base64Util.cs is part of VNLib.Plugins.Essentials.Accounts which is part of the larger 
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

using System.Text.Json;

using VNLib.Utils;
using VNLib.Utils.Memory;

namespace VNLib.Plugins.Essentials.Accounts.MFA.Fido
{
    internal static class Base64Util
    {
        public static byte[] DecodeArray(string base64Data)
        {
            //Alloc buffer with enough room for padding bytes to be appended
            using UnsafeMemoryHandle<byte> buffer = MemoryUtil.UnsafeAlloc<byte>(base64Data.Length + 16);

            ERRNO size = VnEncoding.Base64UrlDecode(base64Data, buffer.Span);

            return buffer
                .AsSpan(0, size)
                .ToArray(); //We need arrays for creating ec point for public keys
        }

        public static T? DeserializeJson<T>(string base64Data)
        {
            //Alloc buffer with enough room for padding bytes to be appended
            using UnsafeMemoryHandle<byte> buffer = MemoryUtil.UnsafeAlloc<byte>(base64Data.Length + 16);

            ERRNO size = VnEncoding.Base64UrlDecode(base64Data, buffer.Span);

            //Recover the json data from the base64 encoded string
            return JsonSerializer.Deserialize<T>(buffer.AsSpan(0, size));
        }

    }
}
