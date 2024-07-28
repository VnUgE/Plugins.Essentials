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
using System.Linq;

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
        /// <param name="manager"></param>
        /// <param name="user">The user to generate the secret for</param>
        /// <returns>The raw secret that was encrypted and stored in the user's object</returns>
        /// <exception cref="OutOfMemoryException"></exception>
        internal static byte[]? TotpSetNewSecret(this MfaAuthManager manager, IUser user)
        {
            ArgumentNullException.ThrowIfNull(manager);
            ArgumentNullException.ThrowIfNull(user);

            //Get the totp processor if it exists
            TotpAuthProcessor? proc = manager.Processors
                    .OfType<TotpAuthProcessor>()
                    .FirstOrDefault();

            //May not be loaded to return null
            if(proc is null)
            {
                return null;
            }
           
            byte[] newSecret = proc.GenerateNewSecret();
         
            user.TotpSetSecret(VnEncoding.ToBase32String(newSecret, false));
            
            return newSecret;
        }

        /// <summary>
        /// Verifies a TOTP code for a given user instance. 
        /// </summary>
        /// <param name="manager"></param>
        /// <param name="user">The user to valid the code against</param>
        /// <param name="code">The TOTP code to verify</param>
        /// <returns>
        /// True if totp is enabled and the code matches, false if the provider is no loaded, or the code does not match
        /// </returns>
        internal static bool TotpVerifyCode(this MfaAuthManager manager, IUser user, uint code)
        {
            ArgumentNullException.ThrowIfNull(manager);
            ArgumentNullException.ThrowIfNull(user);

            TotpAuthProcessor? proc = manager.Processors
                    .OfType<TotpAuthProcessor>()
                    .FirstOrDefault();
                
            return proc is not null && proc.VerifyTOTP(user, code);
        }

        /// <summary>
        /// Determines if TOTP is enabled for the plugin
        /// </summary>
        /// <param name="manager"></param>
        /// <returns>True if the auth manager has a totp processor enabled</returns>
        internal static bool TotpIsEnabled(this MfaAuthManager manager)
        {
            ArgumentNullException.ThrowIfNull(manager);

            return manager.Processors
                    .Where(static p => p.Type == MFAType.TOTP)
                    .Any();
        }
    }
}
