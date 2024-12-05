/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: UserFidoMfaExtensions.cs 
*
* UserFidoMfaExtensions.cs is part of VNLib.Plugins.Essentials.Accounts which is part of the larger 
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
using System.Linq;
using System.Buffers;

using VNLib.Plugins.Essentials.Users;

namespace VNLib.Plugins.Essentials.Accounts.MFA.Fido
{
    /// <summary>
    /// Provides Fido/Webauthn authentication extension methods for users
    /// </summary>
    public static class UserFidoMfaExtensions
    {
        public const string FidoUserStoreKey = "mfa.fido";

        public const int MaxEncodedSize = 1200;     //Aribtrary size limit for the user account object
        public const int AssumedKeySize = 320;      //Based on a p384 key base64 encoded

        /// <summary>
        /// Gets a value that determines if the user has PKI enabled
        /// </summary>
        /// <param name="user"></param>
        /// <returns>True if the user has a PKI key stored in their user account</returns>
        public static bool FidoEnabled(this IUser user) => !string.IsNullOrWhiteSpace(user[FidoUserStoreKey]);

        /// <summary>
        /// Disables all Fido authentication for the current user
        /// </summary>
        /// <param name="user"></param>
        public static void FidoDisable(this IUser user) => user[FidoUserStoreKey] = null!;

        /// <summary>
        /// Attempts to determine if another fido key can be encoded and stored in the 
        /// user's account object. This assumes that the key is roughly 320 bytes
        /// when encoded.
        /// </summary>
        /// <param name="user"></param>
        /// <returns>True if there is enough key space to store another key, false otherwise</returns>
        public static bool FidoCanAddKey(this IUser user)
        {
            string rawData = user[FidoUserStoreKey];
            if (string.IsNullOrWhiteSpace(rawData))
            {
                return true;
            }

            return rawData.Length + AssumedKeySize < MaxEncodedSize;
        }

        /// <summary>
        /// Gets the size of the encoded data stored in the user's account object (in bytes)
        /// </summary>
        /// <param name="user"></param>
        /// <returns>The size of the user encoded data in bytes</returns>
        public static int FidoGetDataSize(this IUser user) => user[FidoUserStoreKey].Length;


        /// <summary>
        /// Stores an array of public keys in the user's account object
        /// </summary>
        /// <param name="user"></param>
        /// <param name="creds">The array of device credentials to store for the user</param>
        public static void FidoSetCredentials(this IUser user, FidoDeviceCredential[]? creds)
            => UserEncodedData.Encode(user, FidoUserStoreKey, creds);

        /// <summary>
        /// Gets all public keys stored in the user's account object
        /// </summary>
        /// <param name="user"></param>
        /// <returns>The array of device credentials if they exist</returns>
        public static FidoDeviceCredential[]? FidoGetAllCredentials(this IUser user)
            => UserEncodedData.Decode<FidoDeviceCredential[]>(user, FidoUserStoreKey);

        /// <summary>
        /// Removes a single pki key by it's id
        /// </summary>
        /// <param name="user"></param>
        /// <param name="credId">The id of the credential to remove</param>
        public static void FidoRemoveCredential(this IUser user, string credId)
        {
            FidoDeviceCredential[]? keys = user.FidoGetAllCredentials();
            if (keys == null)
            {
                return;
            }

            //Remove the key and store a new array without it
            FidoDeviceCredential[]? remaining = keys
                .Where(k => !string.Equals(credId, k.Base64DeviceId, StringComparison.Ordinal))
                .ToArray();

            if (remaining.Length == 0)
            {
                remaining = null;
            }

            FidoSetCredentials(user, remaining);
        }

        /// <summary>
        /// Adds a single pki key to the user's account object, or overwrites
        /// and existing key with the same id
        /// </summary>
        /// <param name="user"></param>
        /// <param name="key">The key to add to the list of user-keys</param>
        public static void FidoAddCredential(this IUser user, FidoDeviceCredential key)
        {
            FidoDeviceCredential[]? keys = user.FidoGetAllCredentials();

            if (keys == null)
            {
                //Add a single key if none exist
                keys = [key];
            }
            else
            {
                //remove the key if it already exists, then append the new key
                keys = keys.Where(k => !string.Equals(key.Base64DeviceId, k.Base64DeviceId, StringComparison.Ordinal))
                    .Append(key)
                    .ToArray();
            }

            user.FidoSetCredentials(keys);
        }
    }
}
