/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: TotpMfaProcessor.cs 
*
* TotpMfaProcessor.cs is part of VNLib.Plugins.Essentials.Accounts which 
* is part of the larger VNLib collection of libraries and utilities.
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
using System.Threading;
using System.Threading.Tasks;
using System.Text.Json.Serialization;

using FluentValidation;

using VNLib.Utils;
using VNLib.Hashing;
using VNLib.Utils.Memory;
using VNLib.Utils.Logging;
using VNLib.Utils.Extensions;
using VNLib.Plugins.Essentials.Users;
using VNLib.Hashing.IdentityUtility;
using VNLib.Plugins.Extensions.Validation;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Users;

namespace VNLib.Plugins.Essentials.Accounts.MFA.Totp
{

    [ConfigurationName("totp_settings")]
    internal sealed class TotpMfaProcessor(PluginBase plugin, IConfigScope pluginConfig) : IMfaProcessor
    {
        private static readonly TotpMessageValidator TotpReqVal = new();

        private readonly TOTPConfig _config = pluginConfig.DeserialzeAndValidate<TOTPConfig>();
        private readonly IUserManager _users = plugin.GetOrCreateSingleton<UserManager>();
        private readonly ILogProvider _log = plugin.Log.CreateScope("TOTP");

        ///<inheritdoc/>
        public string Type => "totp";

        ///<inheritdoc/>
        public bool MethodEnabledForUser(IUser user) => user.TotpEnabled();

        ///<inheritdoc/>
        public bool ArmedForUser(IUser user) => user.TotpEnabled();

        ///<inheritdoc/>
        public bool VerifyResponse(IUser user, JsonElement request)
        {
            //Gracefully try to parse the totp code without raising exceptions if it's not there if not a number
            if (!request.TryGetProperty("code", out JsonElement codeEl)
                || codeEl.ValueKind != JsonValueKind.Number)
            {
                return false;
            }

            return VerifyTOTP(user, codeEl.GetUInt32());
        }

        ///<inheritdoc/>
        public async ValueTask<object?> OnHandleMessageAsync(HttpEntity entity, JsonElement request, IUser user)
        {
            ValErrWebMessage webm = new();

            using TotpRequestMessage? req = request.Deserialize<TotpRequestMessage>();
            if (webm.Assert(req != null, "Empty request message"))
            {
                return webm;
            }

            if (!TotpReqVal.Validate(req, webm))
            {
                return webm;
            }

            //If the request is password protected, verify the password
            if (PasswordProtected(req))
            {
                bool passwordValid = await VerifyPasswordAsync(user, req, webm, entity.EventCancellation);

                if (!passwordValid)
                {
                    return webm;
                }
            }

            switch (req.Action)
            {
                //Enable and update are the same operation
                case "enable":
                case "update":

                    await EnableOrUpdateTotpAsync(entity, user, webm);

                    break;

                case "disable":
                    user.TotpDisable();

                    //Push changes to the database
                    await user.ReleaseAsync(entity.EventCancellation);

                    webm.Result = "Successfully disabled your TOTP authenticator";
                    webm.Success = true;
                    break;

                // Verify just checks the code matches against the stored secret
                // The the future we should wait to enable totp until the code is verified as a UX safe guard
                case "verify":

                    if (webm.Assert(req.VerifyCode.HasValue, "No TOTP code was provided"))
                    {
                        break;
                    }

                    if (VerifyTOTP(user, req.VerifyCode.Value))
                    {
                        webm.Result = "Successfully verified your TOTP code";
                        webm.Success = true;
                        break;
                    }

                    webm.Result = "Your code is not valid, please try again";
                    break;

                default:
                    webm.Result = "Invalid action requested";
                    break;
            }

            return webm;
        }

        ///<inheritdoc/>
        public ValueTask<object?> OnUserGetAsync(HttpEntity entity, IUser user)
        {
            return ValueTask.FromResult<object?>(null);
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
            int currenStep = -_config.TimeWindowSteps;

            Span<byte> stepBuffer = stackalloc byte[sizeof(long)];
            Span<byte> hashBuffer = stackalloc byte[ManagedHash.GetHashSize(_config.HashAlg)];

            //Run the loop at least once to allow a 0 step tight window
            do
            {
                //Calculate the window by multiplying the window by the current step, then add it to the current time offset to produce a new window
                DateTimeOffset window = currentUtc.Add(_config.Period.Multiply(currenStep));

                //calculate the time step
                long timeStep = (long)Math.Floor(window.ToUnixTimeSeconds() / _config.Period.TotalSeconds);

                //try to compute the hash, must always be storable in the buffer
                bool writeResult = BitConverter.TryWriteBytes(stepBuffer, timeStep);
                Debug.Assert(writeResult, "Failed to format the time step buffer because the buffer size was not large enough");

                //If platform is little endian, reverse the byte order
                if (BitConverter.IsLittleEndian)
                {
                    stepBuffer.Reverse();
                }

                ERRNO result = ManagedHash.ComputeHmac(userSecret, stepBuffer, hashBuffer, _config.HashAlg);

                if (result < 1)
                {
                    throw new InternalBufferTooSmallException("Failed to compute TOTP time step hash because the buffer was too small");
                }

                codeMatches |= totpCode == CalcTOTPCode(_config.Digits, hashBuffer[..(int)result]);

                currenStep++;

            } while (currenStep <= _config.TimeWindowSteps);

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
                TOTPCode = ((hash[offset] & 0x7Fu) << 24)
                    | ((hash[offset + 1] & 0xFFu) << 16)
                    | ((hash[offset + 2] & 0xFFu) << 8)
                    | (hash[offset + 3] & 0xFFu);
            }
            else
            {
                //Store the code components (In reverse order for big-endian machines)
                TOTPCode = ((hash[offset + 3] & 0x7Fu) << 24)
                    | ((hash[offset + 2] & 0xFFu) << 16)
                    | ((hash[offset + 1] & 0xFFu) << 8)
                    | (hash[offset] & 0xFFu);
            }
            //calculate the modulus value
            TOTPCode %= (uint)Math.Pow(10, digits);
            return TOTPCode;
        }

        ///<inheritdoc/>
        public void ExtendUpgradePayload(in JwtPayload message, IUser user)
        { }

        private static bool PasswordProtected(TotpRequestMessage req)
        {
            return req.Action switch
            {
                //Verify does not alter the security state for the user
                "verify" => false,

                //Default to pw required
                _ => true
            };
        }

        private async Task<bool> VerifyPasswordAsync(IUser user, TotpRequestMessage req, WebMessage webm, CancellationToken cancellation)
        {
            const string CheckPassword = "Please check your password";

            if (webm.Assert(!string.IsNullOrEmpty(req.Password), CheckPassword))
            {
                return false;
            }

            //Verify password against the user
            ERRNO result = await _users.ValidatePasswordAsync(
                user,
                req.Password,
                PassValidateFlags.None,
                cancellation
            );

            return !webm.Assert(result == UserPassValResult.Success, CheckPassword);
        }

        private async Task EnableOrUpdateTotpAsync(HttpEntity entity, IUser user, WebMessage webm)
        {
            //generate a new secret (passing the buffer which will get copied to an array because the pw bytes can be modified during encryption)
            byte[] secretBuffer = GenerateNewSecret();

            //Alloc output buffer
            IMemoryHandle<byte> outputBuffer = MemoryUtil.SafeAllocNearestPage(1024, zero: true);

            try
            {
                //Encrypt the secret for the client
                ERRNO count = entity.TryEncryptClientData(secretBuffer, outputBuffer.Span);

                if (!count)
                {
                    webm.Result = "There was an error updating your credentials";

                    //If this code is running, the client should have a valid public key stored, but log it anyway
                    _log.Warn("TOTP secret encryption failed, for requested user {uid}", entity.Session.UserID);
                }
                else
                {
                    webm.Result = new TOTPUpdateMessage()
                    {
                        Issuer      = _config.IssuerName,
                        Digits      = _config.Digits,
                        Period      = (int)_config.Period.TotalSeconds,
                        Algorithm   = _config.HashAlg.ToString(),
                        //Convert the secret to base64 string to send to client
                        Base64EncSecret = Convert.ToBase64String(outputBuffer.AsSpan(0, count))
                    };

                    webm.Success = true;

                    //Store secret in the user account
                    user.TotpSetSecret(VnEncoding.ToBase32String(secretBuffer, withPadding: false));

                    //Only write changes to the db of operation was successful
                    await user.ReleaseAsync(entity.EventCancellation);
                }
            }
            finally
            {
                //dispose the output buffer
                outputBuffer.Dispose();
                MemoryUtil.InitializeBlock(secretBuffer);
            }
        }

        /// <summary>
        /// Generates a new TOTP secret according to the system TOTP configuration
        /// </summary>
        /// <returns>The random secret of the configured size</returns>
        internal byte[] GenerateNewSecret()
        {
            return RandomHash.GetRandomBytes(_config.SecretSize);
        }

        private sealed class TOTPUpdateMessage
        {
            [JsonPropertyName("issuer")]
            public string? Issuer { get; set; }

            [JsonPropertyName("digits")]
            public int Digits { get; set; }

            [JsonPropertyName("period")]
            public int Period { get; set; }

            [JsonPropertyName("secret")]
            public string? Base64EncSecret { get; set; }

            [JsonPropertyName("algorithm")]
            public string? Algorithm { get; set; }
        }

        private sealed class TotpRequestMessage(): PrivateStringManager(1)
        {
            [JsonPropertyName("password")]
            public string? Password
            {
                get => this[0];
                set => this[0] = value;
            }

            [JsonPropertyName("action")]
            public string? Action { get; set; }

            [JsonPropertyName("verify_code")]
            public uint? VerifyCode { get; set; }
        }

        sealed class TotpMessageValidator: AbstractValidator<TotpRequestMessage>
        {
            public TotpMessageValidator()
            {
                RuleFor(p => p.Action!)
                    .NotEmpty()
                    .WithMessage("Action must be provided")
                    .Matches("enable|disable|verify|update");

                //Standard resource exhuastion protection (large passwords take time to hash)
                RuleFor(p => p.Password)
                    .MaximumLength(200);
            }
        }
    }
}