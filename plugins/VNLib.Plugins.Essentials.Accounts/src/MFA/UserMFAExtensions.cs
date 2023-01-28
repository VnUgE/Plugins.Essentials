/*
* Copyright (c) 2022 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: UserMFAExtensions.cs 
*
* UserMFAExtensions.cs is part of VNLib.Plugins.Essentials.Accounts which is part of the larger 
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
using System.Text.Json;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using System.Diagnostics.CodeAnalysis;

using VNLib.Hashing;
using VNLib.Utils;
using VNLib.Utils.Memory;
using VNLib.Utils.Extensions;
using VNLib.Hashing.IdentityUtility;
using VNLib.Plugins.Essentials.Users;
using VNLib.Plugins.Essentials.Sessions;
using VNLib.Plugins.Extensions.Loading;

namespace VNLib.Plugins.Essentials.Accounts.MFA
{

    internal static class UserMFAExtensions
    {
        public const string WEBAUTHN_KEY_ENTRY = "mfa.fido";
        public const string TOTP_KEY_ENTRY = "mfa.totp";
        public const string PGP_PUB_KEY = "mfa.pgpp";
        public const string SESSION_SIG_KEY = "mfa.sig";

        /// <summary>
        /// Determines if the user account has an 
        /// </summary>
        /// <param name="user"></param>
        /// <returns>True if any form of MFA is enabled for the user account</returns>
        public static bool MFAEnabled(this IUser user)
        {
            return !(string.IsNullOrWhiteSpace(user[TOTP_KEY_ENTRY]) && string.IsNullOrWhiteSpace(user[WEBAUTHN_KEY_ENTRY]));
        }

        #region totp

        /// <summary>
        /// Recovers the base32 encoded TOTP secret for the current user
        /// </summary>
        /// <param name="user"></param>
        /// <returns>The base32 encoded TOTP secret, or an emtpy string (user spec) if not set</returns>
        public static string MFAGetTOTPSecret(this IUser user) => user[TOTP_KEY_ENTRY];

        /// <summary>
        /// Stores or removes the current user's TOTP secret, stored in base32 format
        /// </summary>
        /// <param name="user"></param>
        /// <param name="secret">The base32 encoded TOTP secret</param>
        public static void MFASetTOTPSecret(this IUser user, string? secret) => user[TOTP_KEY_ENTRY] = secret!;        
     

        /// <summary>
        /// Generates/overwrites the current user's TOTP secret entry and returns a 
        /// byte array of the generated secret bytes
        /// </summary>
        /// <param name="entry">The <see cref="MFAEntry"/> to modify the TOTP configuration of</param>
        /// <returns>The raw secret that was encrypted and stored in the <see cref="MFAEntry"/>, to send to the client</returns>
        /// <exception cref="OutOfMemoryException"></exception>
        public static byte[] MFAGenreateTOTPSecret(this IUser user, MFAConfig config)
        {
            //Generate a random key
            byte[] newSecret = RandomHash.GetRandomBytes(config.TOTPSecretBytes);
            //Store secret in user storage
            user.MFASetTOTPSecret(VnEncoding.ToBase32String(newSecret, false));
            //return the raw secret bytes
            return newSecret;
        }

        /// <summary>
        /// Verfies the supplied TOTP code against the current user's totp codes
        /// This method should not be used for verifying TOTP codes for authentication
        /// </summary>
        /// <param name="user">The user account to verify the TOTP code against</param>
        /// <param name="code">The code to verify</param>
        /// <param name="config">A readonly referrence to the MFA configuration structure</param>
        /// <returns>True if the user has TOTP configured and code matches against its TOTP secret entry, false otherwise</returns>
        /// <exception cref="FormatException"></exception>
        /// <exception cref="OutOfMemoryException"></exception>
        public static bool VerifyTOTP(this MFAConfig config, IUser user, uint code)
        {
            //Get the base32 TOTP secret for the user and make sure its actually set
            string base32Secret = user.MFAGetTOTPSecret();
            if (string.IsNullOrWhiteSpace(base32Secret))
            {
                return false;
            }
            //Alloc buffer with zero o
            using UnsafeMemoryHandle<byte> buffer = MemoryUtil.UnsafeAlloc<byte>(base32Secret.Length, true);
            ERRNO count = VnEncoding.TryFromBase32Chars(base32Secret, buffer);
            //Verify the TOTP using the decrypted secret
            return count && VerifyTOTP(code, buffer.AsSpan(0, count), config);
        }

        private static bool VerifyTOTP(uint totpCode, ReadOnlySpan<byte> userSecret, MFAConfig config)
        {
            //A basic attempt at a constant time TOTP verification, run the calculation a fixed number of times, regardless of the resutls
            bool codeMatches = false;

            //cache current time
            DateTimeOffset currentUtc = DateTimeOffset.UtcNow;
            //Start the current window with the minimum window
            int currenStep = -config.TOTPTimeWindowSteps;
            Span<byte> stepBuffer = stackalloc byte[sizeof(long)];
            Span<byte> hashBuffer = stackalloc byte[(int)config.TOTPAlg];
            //Run the loop at least once to allow a 0 step tight window
            do
            {
                //Calculate the window by multiplying the window by the current step, then add it to the current time offset to produce a new window
                DateTimeOffset window = currentUtc.Add(config.TOTPPeriod.Multiply(currenStep));
                //calculate the time step
                long timeStep = (long)Math.Floor(window.ToUnixTimeSeconds() / config.TOTPPeriod.TotalSeconds);
                //try to compute the hash
                _ = BitConverter.TryWriteBytes(stepBuffer, timeStep) ? 0 : throw new InternalBufferTooSmallException("Failed to format TOTP time step");
                //If platform is little endian, reverse the byte order
                if (BitConverter.IsLittleEndian)
                {
                    stepBuffer.Reverse();
                }
                ERRNO result = ManagedHash.ComputeHmac(userSecret, stepBuffer, hashBuffer, config.TOTPAlg);
                //try to compute the hash of the time step
                if (result < 1)
                {
                    throw new InternalBufferTooSmallException("Failed to compute TOTP time step hash because the buffer was too small");
                }
                //Hash bytes
                ReadOnlySpan<byte> hash = hashBuffer[..(int)result];
                //compute the TOTP code and compare it to the supplied, then store the result
                codeMatches |= (totpCode == CalcTOTPCode(hash, config));
                //next step
                currenStep++;
            } while (currenStep <= config.TOTPTimeWindowSteps);

            return codeMatches;
        }

        private static uint CalcTOTPCode(ReadOnlySpan<byte> hash, MFAConfig config)
        {
            //Calculate the offset, RFC defines, the lower 4 bits of the last byte in the hash output
            byte offset = (byte)(hash[^1] & 0x0Fu);

            uint TOTPCode;
            if (BitConverter.IsLittleEndian)
            {
                //Store the code components
                TOTPCode = (hash[offset] & 0x7Fu) << 24 | (hash[offset + 1] & 0xFFu) << 16 | (hash[offset + 2] & 0xFFu) << 8 | hash[offset + 3] & 0xFFu;
            }
            else
            {
                //Store the code components (In reverse order for big-endian machines)
                TOTPCode = (hash[offset + 3] & 0x7Fu) << 24 | (hash[offset + 2] & 0xFFu) << 16 | (hash[offset + 1] & 0xFFu) << 8 | hash[offset] & 0xFFu;
            }
            //calculate the modulus value
            TOTPCode %= (uint)Math.Pow(10, config.TOTPDigits);
            return TOTPCode;
        }

        #endregion

        #region loading

        const string MFA_CONFIG_KEY = "mfa";

        /// <summary>
        /// Gets the plugins ambient <see cref="PasswordHashing"/> if loaded, or loads it if required. This class will
        /// be unloaded when the plugin us unloaded.
        /// </summary>
        /// <param name="plugin"></param>
        /// <returns>The ambient <see cref="PasswordHashing"/></returns>
        /// <exception cref="OverflowException"></exception>
        /// <exception cref="KeyNotFoundException"></exception>
        /// <exception cref="ObjectDisposedException"></exception>
        public static MFAConfig? GetMfaConfig(this PluginBase plugin)
        {
            static MFAConfig? LoadMfaConfig(PluginBase pbase)
            {
                //Try to get the configuration object
                IReadOnlyDictionary<string, JsonElement>? conf = pbase.TryGetConfig(MFA_CONFIG_KEY);

                if (conf == null)
                {
                    return null;
                }
                //Init mfa config
                MFAConfig mfa = new(conf);

                //Recover secret from config and dangerous 'lazy load'
                _ = pbase.ObserveTask(async () =>
                {
                    mfa.MFASecret = await pbase.TryGetSecretAsync("mfa_secret").ToJsonWebKey();

                }, 50);

                return mfa;
            }
            
            plugin.ThrowIfUnloaded();
            //Get/load the passwords one time only
            return LoadingExtensions.GetOrCreateSingleton(plugin, LoadMfaConfig);
        }

        #endregion

        #region pgp

        private class PgpMfaCred
        {
            [JsonPropertyName("p")]
            public string? SpkiPublicKey { get; set; }

            [JsonPropertyName("c")]
            public string? CurveFriendlyName { get; set; }
        }
        

        /// <summary>
        /// Gets the stored PGP public key for the user
        /// </summary>
        /// <param name="user"></param>
        /// <returns>The stored PGP signature key </returns>
        public static string MFAGetPGPPubKey(this IUser user) => user[PGP_PUB_KEY];

        public static void MFASetPGPPubKey(this IUser user, string? pubKey) => user[PGP_PUB_KEY] = pubKey!;

        public static void VerifySignedData(string data)
        {
            
        }

        #endregion

        #region webauthn

        #endregion

        /// <summary>
        /// Recovers a signed MFA upgrade JWT and verifies its authenticity, and confrims its not expired,
        /// then recovers the upgrade mssage
        /// </summary>
        /// <param name="config"></param>
        /// <param name="upgradeJwtString">The signed JWT upgrade message</param>
        /// <param name="upgrade">The recovered upgrade</param>
        /// <param name="base64sessionSig">The stored base64 encoded signature from the session that requested an upgrade</param>
        /// <returns>True if the upgrade was verified, not expired, and was recovered from the signed message, false otherwise</returns>
        public static bool RecoverUpgrade(this MFAConfig config, ReadOnlySpan<char> upgradeJwtString, ReadOnlySpan<char> base64sessionSig, [NotNullWhen(true)] out MFAUpgrade? upgrade)
        {
            //Verifies a jwt stored signature against the actual signature
            static bool VerifyStoredSig(ReadOnlySpan<char> base64string, ReadOnlySpan<byte> signature)
            {
                using UnsafeMemoryHandle<byte> buffer = MemoryUtil.UnsafeAlloc<byte>(base64string.Length, true);

                //Recover base64
                ERRNO count = VnEncoding.TryFromBase64Chars(base64string, buffer.Span);
                
                //Compare
                return CryptographicOperations.FixedTimeEquals(signature, buffer.Span[..(int)count]);
            }

            //Verify config secret
            _ = config.MFASecret ?? throw new InvalidOperationException("MFA config is missing required upgrade signing key");

            upgrade = null;
            
            //Parse jwt
            using JsonWebToken jwt = JsonWebToken.Parse(upgradeJwtString);
            
            if (!jwt.VerifyFromJwk(config.MFASecret))
            {
                return false;
            }

            if(!VerifyStoredSig(base64sessionSig, jwt.SignatureData))
            {
                return false;
            }
            
            //get request body
            using JsonDocument doc = jwt.GetPayload();
            
            //Recover issued at time
            DateTimeOffset iat = DateTimeOffset.FromUnixTimeMilliseconds(doc.RootElement.GetProperty("iat").GetInt64());

            //Verify its not timed out
            if (iat.Add(config.UpgradeValidFor) < DateTimeOffset.UtcNow)
            {
                //expired
                return false;
            }

            //Recover the upgrade message
            upgrade = doc.RootElement.GetProperty("upgrade").Deserialize<MFAUpgrade>();
            return upgrade != null;
        }


        /// <summary>
        /// Generates an upgrade for the requested user, using the highest prirotiy method
        /// </summary>
        /// <param name="login">The message from the user requesting the login</param>
        /// <returns>A signed upgrade message the client will pass back to the server after the MFA verification</returns>
        /// <exception cref="InvalidOperationException"></exception>
        public static Tuple<string, string>? MFAGetUpgradeIfEnabled(this IUser user, MFAConfig? conf, LoginMessage login, string pwClientData)
        {
            //Webauthn config


            //Search for totp secret entry
            string base32Secret = user.MFAGetTOTPSecret();

            //Check totp entry
            if (!string.IsNullOrWhiteSpace(base32Secret))
            {
                //Verify config secret
                _ = conf?.MFASecret ?? throw new InvalidOperationException("MFA config is missing required upgrade signing key");
                
                //setup the upgrade
                MFAUpgrade upgrade = new()
                {
                    //Set totp upgrade type
                    Type = MFAType.TOTP,
                    //Store login message details
                    UserName = login.UserName,
                    ClientID = login.ClientID,
                    Base64PubKey = login.ClientPublicKey,
                    ClientLocalLanguage = login.LocalLanguage,
                    PwClientData = pwClientData
                };

                //Init jwt for upgrade
                return GetUpgradeMessage(upgrade, conf.MFASecret, conf.UpgradeValidFor);
            }
            return null;
        }

        private static Tuple<string, string> GetUpgradeMessage(MFAUpgrade upgrade, ReadOnlyJsonWebKey secret, TimeSpan expires)
        {
            //Add some random entropy to the upgrade message, to help prevent forgery
            string entropy = RandomHash.GetRandomBase32(16);
            //Init jwt
            using JsonWebToken upgradeJwt = new();
            upgradeJwt.WriteHeader(secret.JwtHeader);
            //Write claims
            upgradeJwt.InitPayloadClaim()
                .AddClaim("iat", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds())
                .AddClaim("upgrade", upgrade)
                .AddClaim("type", upgrade.Type.ToString().ToLower())
                .AddClaim("expires", expires.TotalSeconds)
                .AddClaim("a", entropy)
                .CommitClaims();
            
            //Sign with jwk
            upgradeJwt.SignFromJwk(secret);
            
            //compile and return jwt upgrade
            return new(upgradeJwt.Compile(), Convert.ToBase64String(upgradeJwt.SignatureData));
        }

        public static void MfaUpgradeSignature(this in SessionInfo session, string? base64Signature) => session[SESSION_SIG_KEY] = base64Signature!;

        public static string? MfaUpgradeSignature(this in SessionInfo session) => session[SESSION_SIG_KEY];
    }
}
