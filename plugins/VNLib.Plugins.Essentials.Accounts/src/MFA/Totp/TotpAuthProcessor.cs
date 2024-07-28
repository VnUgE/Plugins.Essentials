/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: LoginEndpoint.cs 
*
* LoginEndpoint.cs is part of VNLib.Plugins.Essentials.Accounts which is part of the larger 
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
using System.Diagnostics;

using VNLib.Utils;
using VNLib.Hashing;
using VNLib.Utils.Memory;
using VNLib.Plugins.Essentials.Users;
using VNLib.Hashing.IdentityUtility;


namespace VNLib.Plugins.Essentials.Accounts.MFA.Totp
{
    internal sealed class TotpAuthProcessor(TOTPConfig config) : IMfaProcessor
    {
        ///<inheritdoc/>
        public MFAType Type => MFAType.TOTP;

        ///<inheritdoc/>
        public bool MethodEnabledForUser(IUser user) => user.TotpEnabled();

        ///<inheritdoc/>
        public bool VerifyResponse(MfaChallenge upgrade, IUser user, JsonDocument result)
        {
            if (!result.RootElement.TryGetProperty("code", out JsonElement codeEl)
                || codeEl.ValueKind != JsonValueKind.Number)
            {
                return false;
            }

            return VerifyTOTP(user, codeEl.GetUInt32());
        }

        /// <summary>
        /// Verfies the supplied TOTP code against the current user's totp codes
        /// This method should not be used for verifying TOTP codes for authentication
        /// </summary>
        /// <param name="user">The user account to verify the TOTP code against</param>
        /// <param name="code">The code to verify</param>
        /// <returns>True if the user has TOTP configured and code matches against its TOTP secret entry, false otherwise</returns>
        /// <exception cref="FormatException"></exception>
        /// <exception cref="OutOfMemoryException"></exception>
        internal bool VerifyTOTP(IUser user, uint code)
        {
            //Get the base32 TOTP secret for the user and make sure its actually set
            string base32Secret = user.TotpGetSecret();

            if (string.IsNullOrWhiteSpace(base32Secret))
            {
                return false;
            }

            int length = base32Secret.Length;
            bool isValid;

            if (length > 256)
            {
                using UnsafeMemoryHandle<byte> buffer = MemoryUtil.UnsafeAllocNearestPage(base32Secret.Length, true);

                ERRNO count = VnEncoding.TryFromBase32Chars(base32Secret, buffer.Span);

                //Verify the TOTP using the decrypted secret
                isValid = count && VerifyTotpCode(code, buffer.AsSpan(0, count));

                MemoryUtil.InitializeBlock(
                    ref buffer.GetReference(),
                    buffer.IntLength
                );
            }
            else
            {
                Span<byte> buffer = stackalloc byte[base32Secret.Length];

                ERRNO count = VnEncoding.TryFromBase32Chars(base32Secret, buffer);

                //Verify the TOTP using the decrypted secret
                isValid = count && VerifyTotpCode(code, buffer[..(int)count]);

                MemoryUtil.InitializeBlock(buffer);
            }

            return isValid;
        }

        private bool VerifyTotpCode(uint totpCode, ReadOnlySpan<byte> userSecret)
        {
            /*
             * A basic attempt at a constant time TOTP verification, run 
             * the calculation a fixed number of times, regardless of the resutls
             */
            bool codeMatches = false;

            //cache current time
            DateTimeOffset currentUtc = DateTimeOffset.UtcNow;

            //Start the current window with the minimum window
            int currenStep = -config.TimeWindowSteps;

            Span<byte> stepBuffer = stackalloc byte[sizeof(long)];
            Span<byte> hashBuffer = stackalloc byte[(int)config.HashAlg];

            //Run the loop at least once to allow a 0 step tight window
            do
            {
                //Calculate the window by multiplying the window by the current step, then add it to the current time offset to produce a new window
                DateTimeOffset window = currentUtc.Add(config.Period.Multiply(currenStep));

                //calculate the time step
                long timeStep = (long)Math.Floor(window.ToUnixTimeSeconds() / config.Period.TotalSeconds);

                //try to compute the hash, must always be storable in the buffer
                bool writeResult = BitConverter.TryWriteBytes(stepBuffer, timeStep);
                Debug.Assert(writeResult, "Failed to format the time step buffer because the buffer size was not large enough");

                //If platform is little endian, reverse the byte order
                if (BitConverter.IsLittleEndian)
                {
                    stepBuffer.Reverse();
                }

                ERRNO result = ManagedHash.ComputeHmac(userSecret, stepBuffer, hashBuffer, config.HashAlg);

                if (result < 1)
                {
                    throw new InternalBufferTooSmallException("Failed to compute TOTP time step hash because the buffer was too small");
                }

                codeMatches |= totpCode == CalcTOTPCode(config.Digits, hashBuffer[..(int)result]);

                currenStep++;

            } while (currenStep <= config.TimeWindowSteps);

            return codeMatches;
        }

        private static uint CalcTOTPCode(int digits, ReadOnlySpan<byte> hash)
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
            TOTPCode %= (uint)Math.Pow(10, digits);
            return TOTPCode;
        }

        public void ExtendUpgradePayload(in JwtPayload message, IUser user)
        { }

        /// <summary>
        /// Generates a new TOTP secret according to the system TOTP configuration
        /// </summary>
        /// <returns>The random secret of the configured size</returns>
        public byte[] GenerateNewSecret()
        {
            return RandomHash.GetRandomBytes(config.SecretSize);
        }
    }
}