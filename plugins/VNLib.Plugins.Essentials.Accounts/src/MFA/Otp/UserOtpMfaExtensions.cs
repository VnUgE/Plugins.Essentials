/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: UserPkiMfaExtensions.cs 
*
* UserPkiMfaExtensions.cs is part of VNLib.Plugins.Essentials.Accounts which is part 
* of the larger VNLib collection of libraries and utilities.
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

using VNLib.Utils.IO;
using VNLib.Utils.Extensions;
using VNLib.Hashing.IdentityUtility;
using VNLib.Plugins.Essentials.Users;

namespace VNLib.Plugins.Essentials.Accounts.MFA.Otp
{

    /// <summary>
    /// Provides user extension methods for PKI specific MFA operations
    /// </summary>
    public static class UserOtpMfaExtensions
    {
        /// <summary>
        /// The key used to store the user's encoded Otp public
        /// keys in their account object
        /// </summary>
        public const string OtpUserStoreKey = "mfa.pki";

        public const int MaxEncodedSize = 1200;     //Aribtrary size limit for the user account object
        public const int AssumedKeySize = 320;      //Based on a p384 key base64 encoded

        /// <summary>
        /// Gets a value that determines if the user has PKI enabled
        /// </summary>
        /// <param name="user"></param>
        /// <returns>True if the user has a PKI key stored in their user account</returns>
        public static bool OtpAuthEnabled(this IUser user) => !string.IsNullOrWhiteSpace(user[OtpUserStoreKey]);

        /// <summary>
        /// Disables PKI authentication for the current user
        /// </summary>
        /// <param name="user"></param>
        public static void OtpDisable(this IUser user) => user[OtpUserStoreKey] = null!;

        /// <summary>
        /// Attempts to determine if another key can be encoded and stored in the 
        /// user's account object. This assumes that the key is roughly 320 bytes
        /// when encoded.
        /// </summary>
        /// <param name="user"></param>
        /// <returns>True if there is enough key space to store another key, false otherwise</returns>
        public static bool OtpCanAddKey(this IUser user)
        {
            string rawData = user[OtpUserStoreKey];
            if (string.IsNullOrWhiteSpace(rawData))
            {
                return true;
            }

            return rawData.Length + AssumedKeySize < MaxEncodedSize;
        }

        /// <summary>
        /// Gets the size of the user's stored PKI key data
        /// </summary>
        /// <param name="user"></param>
        /// <returns>The size in bytes of the stored pki key data</returns>
        public static int OtpGetDataSize(this IUser user) => user[OtpUserStoreKey].Length;

        /// <summary>
        /// Verifies a PKI login JWT against the user's stored login key data
        /// </summary>
        /// <param name="user">The user requesting a login</param>
        /// <param name="jwt">The login jwt to verify</param>
        /// <param name="keyId">The id of the key that generated the request, it must match the id of the stored key</param>
        /// <returns>True if the user has PKI enabled, the key was recovered, the key id matches, and the JWT signature is verified</returns>
        public static bool OtpVerifyUserJWT(this IUser user, JsonWebToken jwt, string keyId)
        {
            /*
             * Since multiple keys can be stored, we need to recover the key that matches the desired key id
             */
            OtpAuthPublicKey? pub = user.OtpGetAllPublicKeys()
                ?.FirstOrDefault(p => string.Equals(keyId, p.KeyId, StringComparison.Ordinal));

            if (pub == null)
            {
                return false;
            }

            //verify the jwt
            return jwt.VerifyFromJwk(pub);
        }

        /// <summary>
        /// Stores an array of public keys in the user's account object
        /// </summary>
        /// <param name="user"></param>
        /// <param name="authKeys">The array of jwk format keys to store for the user</param>
        public static void OtpSetPublicKeys(this IUser user, OtpAuthPublicKey[]? authKeys)
            => UserEncodedData.Encode(user, OtpUserStoreKey, authKeys);

        /// <summary>
        /// Gets all public keys stored in the user's account object
        /// </summary>
        /// <param name="user"></param>
        /// <returns>The array of public keys if the exist</returns>
        public static OtpAuthPublicKey[]? OtpGetAllPublicKeys(this IUser user)
            => UserEncodedData.Decode<OtpAuthPublicKey[]>(user, OtpUserStoreKey);

        /// <summary>
        /// Removes a single pki key by it's id
        /// </summary>
        /// <param name="user"></param>
        /// <param name="keyId">The id of the key to remove</param>
        public static void OtpRemovePublicKey(this IUser user, string keyId)
        {
            OtpAuthPublicKey[]? keys = user.OtpGetAllPublicKeys();
            if (keys == null)
            {
                return;
            }

            //Remove the key and store a new array without it
            OtpAuthPublicKey[]? remaining = keys
                .Where(k => !string.Equals(keyId, k.KeyId, StringComparison.Ordinal))
                .ToArray();

            //If there are no keys left, set the user's key data to null
            if (remaining.Length == 0)
            {
                remaining = null;
            }

            OtpSetPublicKeys(user, remaining);
        }

        /// <summary>
        /// Adds a single pki key to the user's account object, or overwrites
        /// and existing key with the same id
        /// </summary>
        /// <param name="user"></param>
        /// <param name="key">The key to add to the list of user-keys</param>
        public static void OtpAddPublicKey(this IUser user, OtpAuthPublicKey key)
        {
            OtpAuthPublicKey[]? keys = user.OtpGetAllPublicKeys();

            if (keys == null)
            {
                //Add a single key if none exist
                keys = [key];
            }
            else
            {
                //remove the key if it already exists, then append the new key
                keys = keys.Where(k => !string.Equals(key.KeyId, k.KeyId, StringComparison.Ordinal))
                    .Append(key)
                    .ToArray();
            }

            user.OtpSetPublicKeys(keys);
        }
    }
}
