/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: UserTotpMfaExtensions.cs 
*
* UserTotpMfaExtensions.cs is part of VNLib.Plugins.Essentials.Accounts which is 
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

using System;

using VNLib.Hashing;
using VNLib.Utils;
using VNLib.Plugins.Essentials.Users;

namespace VNLib.Plugins.Essentials.Accounts.MFA.Totp
{
    public static class UserTotpMfaExtensions
    {
        public const string TOTP_KEY_ENTRY = "mfa.totp";

        /// <summary>
        /// Recovers the base32 encoded TOTP secret for the current user
        /// </summary>
        /// <param name="user"></param>
        /// <returns>The base32 encoded TOTP secret, or an emtpy string (user spec) if not set</returns>
        public static string TotpGetSecret(this IUser user) => user[TOTP_KEY_ENTRY];

        /// <summary>
        /// Stores or removes the current user's TOTP secret, stored in base32 format
        /// </summary>
        /// <param name="user"></param>
        /// <param name="secret">The base32 encoded TOTP secret</param>
        public static void TotpSetSecret(this IUser user, string? secret) => user[TOTP_KEY_ENTRY] = secret!;

        /// <summary>
        /// Determines if the user account has TOTP enabled
        /// </summary>
        /// <param name="user"></param>
        /// <returns>True if the user has totp enabled, false otherwise</returns>
        public static bool TotpEnabled(this IUser user) => !string.IsNullOrWhiteSpace(user[TOTP_KEY_ENTRY]);

        /// <summary>
        /// Disables TOTP for the current user
        /// </summary>
        /// <param name="user"></param>
        public static void TotpDisable(this IUser user) => user[TOTP_KEY_ENTRY] = null!;

        /// <summary>
        /// Generates/overwrites the current user's TOTP secret entry and returns a 
        /// byte array of the generated secret bytes
        /// </summary>
        /// <param name="config">The system MFA configuration</param>
        /// <returns>The raw secret that was encrypted and stored in the user's object</returns>
        /// <exception cref="OutOfMemoryException"></exception>
        internal static byte[] MFAGenreateTOTPSecret(this IUser user, MFAConfig config)
        {
            _ = config.TOTPConfig ?? throw new NotSupportedException("The loaded configuration does not support TOTP");
            //Generate a random key
            byte[] newSecret = RandomHash.GetRandomBytes(config.TOTPConfig.TOTPSecretBytes);
            //Store secret in user storage
            user.TotpSetSecret(VnEncoding.ToBase32String(newSecret, false));
            //return the raw secret bytes
            return newSecret;
        }

     
    }
}
