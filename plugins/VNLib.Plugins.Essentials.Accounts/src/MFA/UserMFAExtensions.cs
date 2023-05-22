/*
* Copyright (c) 2023 Vaughn Nugent
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
using System.Buffers;
using System.Text.Json;
using System.Collections.Generic;

using VNLib.Hashing;
using VNLib.Utils;
using VNLib.Utils.Memory;
using VNLib.Utils.Extensions;
using VNLib.Hashing.IdentityUtility;
using VNLib.Plugins.Essentials.Users;
using VNLib.Plugins.Essentials.Sessions;

namespace VNLib.Plugins.Essentials.Accounts.MFA
{

    internal static class UserMFAExtensions
    {
        public const string WEBAUTHN_KEY_ENTRY = "mfa.fido";
        public const string TOTP_KEY_ENTRY = "mfa.totp";
        public const string SESSION_SIG_KEY = "mfa.sig";

        public const string USER_PKI_ENTRY = "mfa.pki";

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
        /// Determines if the user account has TOTP enabled
        /// </summary>
        /// <param name="user"></param>
        /// <returns>True if the user has totp enabled, false otherwise</returns>
        public static bool MFATotpEnabled(this IUser user) => !string.IsNullOrWhiteSpace(user[TOTP_KEY_ENTRY]);

        /// <summary>
        /// Generates/overwrites the current user's TOTP secret entry and returns a 
        /// byte array of the generated secret bytes
        /// </summary>
        /// <param name="entry">The <see cref="MFAEntry"/> to modify the TOTP configuration of</param>
        /// <returns>The raw secret that was encrypted and stored in the <see cref="MFAEntry"/>, to send to the client</returns>
        /// <exception cref="OutOfMemoryException"></exception>
        public static byte[] MFAGenreateTOTPSecret(this IUser user, MFAConfig config)
        {
            _ = config.TOTPConfig ?? throw new NotSupportedException("The loaded configuration does not support TOTP");
            //Generate a random key
            byte[] newSecret = RandomHash.GetRandomBytes(config.TOTPConfig.TOTPSecretBytes);
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
            if (!config.TOTPEnabled || string.IsNullOrWhiteSpace(base32Secret))
            {
                return false;
            }
            //Alloc buffer with zero o
            using UnsafeMemoryHandle<byte> buffer = MemoryUtil.UnsafeAlloc(base32Secret.Length, true);
            ERRNO count = VnEncoding.TryFromBase32Chars(base32Secret, buffer);
            //Verify the TOTP using the decrypted secret
            return count && VerifyTOTP(code, buffer.AsSpan(0, count), config.TOTPConfig);
        }

        private static bool VerifyTOTP(uint totpCode, ReadOnlySpan<byte> userSecret, TOTPConfig config)
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

        private static uint CalcTOTPCode(ReadOnlySpan<byte> hash, TOTPConfig config)
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

        #region PKI
        const int JWK_KEY_BUFFER_SIZE = 2048;

        /// <summary>
        /// Gets a value that determines if the user has PKI enabled
        /// </summary>
        /// <param name="user"></param>
        /// <returns>True if the user has a PKI key stored in their user account</returns>
        public static bool PKIEnabled(this IUser user) => !string.IsNullOrWhiteSpace(user[USER_PKI_ENTRY]);

        /// <summary>
        /// Verifies a PKI login JWT against the user's stored login key data
        /// </summary>
        /// <param name="user">The user requesting a login</param>
        /// <param name="jwt">The login jwt to verify</param>
        /// <param name="keyId">The id of the key that generated the request, it must match the id of the stored key</param>
        /// <returns>True if the user has PKI enabled, the key was recovered, the key id matches, and the JWT signature is verified</returns>
        public static bool PKIVerifyUserJWT(this IUser user, JsonWebToken jwt, string keyId)
        {
            //Recover key data from user, it may not be enabled
            using ReadOnlyJsonWebKey? jwk = RecoverKey(user);

            if(jwk == null)
            {
                return false;
            }

            //Confim the key id matches
            if(!keyId.Equals(jwk.KeyId, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            //verify the jwt
            return jwt.VerifyFromJwk(jwk);
        }

        public static void PKISetUserKey(this IUser user, IReadOnlyDictionary<string, string>? keyFields) 
        {
            //Serialize the key data
            byte[] keyData = JsonSerializer.SerializeToUtf8Bytes(keyFields, Statics.SR_OPTIONS);

            //convert to base32 string before writing user data
            string base64 = Convert.ToBase64String(keyData);

            //Store key data
            user[USER_PKI_ENTRY] = base64;
        }

        private static ReadOnlyJsonWebKey? RecoverKey(IUser user)
        {
            string? keyData = user[USER_PKI_ENTRY];

            if(string.IsNullOrEmpty(keyData))
            {
                return null;
            }

            //Get buffer to recover the key data from
            byte[] buffer = ArrayPool<byte>.Shared.Rent(JWK_KEY_BUFFER_SIZE);
            try
            {
                //Recover base64 bytes from key data
                ERRNO bytes = VnEncoding.TryFromBase64Chars(keyData, buffer);
                if (!bytes)
                {
                    return null;
                }
                //Recover json from the decoded binary data
                return new ReadOnlyJsonWebKey(buffer.AsSpan(0, bytes));
            }
            finally
            {
                MemoryUtil.InitializeBlock(buffer.AsSpan());
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        #endregion

        #region webauthn

        #endregion

        private static HashAlg SigingAlg { get; } = HashAlg.SHA256;

        private static ReadOnlyMemory<byte> UpgradeHeader { get; } = CompileJwtHeader();

        private static byte[] CompileJwtHeader()
        {
            Dictionary<string, string> header = new()
            {
                { "alg","HS256" },
                { "typ", "JWT" }
            };
            return JsonSerializer.SerializeToUtf8Bytes(header);
        }

        /// <summary>
        /// Recovers a signed MFA upgrade JWT and verifies its authenticity, and confrims its not expired,
        /// then recovers the upgrade mssage
        /// </summary>
        /// <param name="config"></param>
        /// <param name="upgradeJwtString">The signed JWT upgrade message</param>
        /// <param name="base32Secret">The stored base64 encoded signature from the session that requested an upgrade</param>
        /// <returns>True if the upgrade was verified, not expired, and was recovered from the signed message, false otherwise</returns>
        public static MFAUpgrade? RecoverUpgrade(this MFAConfig config, string upgradeJwtString, string base32Secret)
        {
            //Parse jwt
            using JsonWebToken jwt = JsonWebToken.Parse(upgradeJwtString);

            //Recover the secret key
            byte[] secret = VnEncoding.FromBase32String(base32Secret)!;
            try
            {
                //Verify the signature
                if (!jwt.Verify(secret, SigingAlg))
                {
                    return null;
                }
            }
            finally
            {
                //Erase secret
                MemoryUtil.InitializeBlock(secret.AsSpan());
            }
            //Valid
            
            //get request body
            using JsonDocument doc = jwt.GetPayload();
            
            //Recover issued at time
            DateTimeOffset iat = DateTimeOffset.FromUnixTimeMilliseconds(doc.RootElement.GetProperty("iat").GetInt64());

            //Verify its not timed out
            if (iat.Add(config.UpgradeValidFor) < DateTimeOffset.UtcNow)
            {
                //expired
                return null;
            }

            //Recover the upgrade message
            return doc.RootElement.GetProperty("upgrade").Deserialize<MFAUpgrade>();
        }


        /// <summary>
        /// Generates an upgrade for the requested user, using the highest prirotiy method
        /// </summary>
        /// <param name="login">The message from the user requesting the login</param>
        /// <returns>A signed upgrade message the client will pass back to the server after the MFA verification</returns>
        /// <exception cref="InvalidOperationException"></exception>
        public static MfaUpgradeMessage? MFAGetUpgradeIfEnabled(this IUser user, MFAConfig? conf, LoginMessage login)
        {
            //Webauthn config


            //Search for totp secret entry
            string base32Secret = user.MFAGetTOTPSecret();

            //Check totp entry
            if (!string.IsNullOrWhiteSpace(base32Secret))
            {
                
                //setup the upgrade
                MFAUpgrade upgrade = new()
                {
                    //Set totp upgrade type
                    Type = MFAType.TOTP,
                    //Store login message details
                    UserName = login.UserName,
                    ClientId = login.ClientId,
                    PublicKey = login.ClientPublicKey,
                    ClientLocalLanguage = login.LocalLanguage,
                };

                //Init jwt for upgrade
                return GetUpgradeMessage(upgrade, conf);
            }
            return null;
        }

        private static MfaUpgradeMessage GetUpgradeMessage(MFAUpgrade upgrade, MFAConfig config)
        {
            //Add some random entropy to the upgrade message, to help prevent forgery
            string entropy = RandomHash.GetRandomBase32(config.NonceLenBytes);
            //Init jwt
            using JsonWebToken upgradeJwt = new();
            //Add header
            upgradeJwt.WriteHeader(UpgradeHeader.Span);
            //Write claims
            upgradeJwt.InitPayloadClaim()
                .AddClaim("iat", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds())
                .AddClaim("upgrade", upgrade)
                .AddClaim("type", upgrade.Type.ToString().ToLower(null))
                .AddClaim("expires", config.UpgradeValidFor.TotalSeconds)
                .AddClaim("a", entropy)
                .CommitClaims();

            //Generate a new random secret
            byte[] secret = RandomHash.GetRandomBytes(config.UpgradeKeyBytes);

            //sign jwt
            upgradeJwt.Sign(secret, SigingAlg);

            //compile and return jwt upgrade
            return new(upgradeJwt.Compile(), VnEncoding.ToBase32String(secret));
        }

        public static void MfaUpgradeSecret(this in SessionInfo session, string? base32Signature) => session[SESSION_SIG_KEY] = base32Signature!;

        public static string? MfaUpgradeSecret(this in SessionInfo session) => session[SESSION_SIG_KEY];
    }

    readonly record struct MfaUpgradeMessage(string ClientJwt, string SessionKey);
}
