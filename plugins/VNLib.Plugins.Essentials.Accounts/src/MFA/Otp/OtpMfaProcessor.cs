/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: OtpMfaProcessor.cs 
*
* OtpMfaProcessor.cs is part of VNLib.Plugins.Essentials.Accounts which 
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
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text.Json.Serialization;

using FluentValidation;

using VNLib.Hashing.IdentityUtility;
using VNLib.Utils;
using VNLib.Utils.Memory;
using VNLib.Utils.Logging;
using VNLib.Plugins.Essentials.Users;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Validation;
using VNLib.Plugins.Extensions.Loading.Users;

namespace VNLib.Plugins.Essentials.Accounts.MFA.Otp
{

    [ConfigurationName("pkotp", Required = false)]
    internal sealed class OtpMfaProcessor(PluginBase plugin) : IMfaProcessor
    {

        /*
         * I am only supporting EC keys for size reasons, user objects are limited in back-end size and keys can 
         * take up large ammounts of data.
         */
        private static readonly ImmutableArray<string> AllowedCurves = ["P-256", "P-384", "P-521"];
        private static readonly ImmutableArray<string> AllowedAlgs = ["ES256", "ES384", "ES512"];
        private static readonly OtpMessageValidator OtpReqVal = new();
        public static readonly OtpPublicKeyValidator OtpKeyValidator = new();

        private readonly IUserManager _users = plugin.GetOrCreateSingleton<UserManager>();
        private readonly ILogProvider _log = plugin.Log.CreateScope("PKOTP");

        ///<inheritdoc/>
        public string Type => "pkotp";

        ///<inheritdoc/>
        public void ExtendUpgradePayload(in JwtPayload message, IUser user)
        { }

        ///<inheritdoc/>
        public bool MethodEnabledForUser(IUser user) => user.OtpAuthEnabled();

        ///<inheritdoc/>
        public bool ArmedForUser(IUser user) => false;  //OTP is not an MFA Method, so it cannot protect accounts

        ///<inheritdoc/>
        public ValueTask<object?> OnUserGetAsync(HttpEntity entity, IUser user)
        {
            return ValueTask.FromResult<object?>(new UserGetResult
            {
                CanAddKeys      = user.OtpCanAddKey(),
                Keys            = user.OtpGetAllPublicKeys() ?? [],
                DataSize        = user.OtpGetDataSize(),
                MaxSize         = UserOtpMfaExtensions.MaxEncodedSize
            });
        }

        ///<inheritdoc/>
        public bool VerifyResponse(IUser user, JsonElement request)
        {
            return false;
        }

        ///<inheritdoc/>
        public async ValueTask<object?> OnHandleMessageAsync(HttpEntity entity, JsonElement request, IUser user)
        {
            WebMessage webm = new();

            using OtpRequestMessage? req = request.Deserialize<OtpRequestMessage>();

            if (webm.Assert(req != null, "Empty request message"))
            {
                return webm;
            }

            if (!OtpReqVal.Validate(req, webm))
            {
                return webm;
            }

            //If the request is password protected, verify the password
            if (IsPasswordProtected(req))
            {
                bool passwordValid = await VerifyPasswordAsync(user, req, webm, entity.EventCancellation);

                if (!passwordValid)
                {
                    return webm;
                }
            }

            switch (req.Action)
            {
                case "add_key":

                    //If validation passed for this action, the key object is not null and valid 
                    AddPublicKey(user, webm, req.AddKey!);

                    //Push changes to the database
                    await user.ReleaseAsync(entity.EventCancellation);

                    break;

                case "remove_key":

                    if(webm.Assert(req.DeleteKeyId != null, "No key id provided"))
                    {
                        return webm;
                    }

                    user.OtpRemovePublicKey(req.DeleteKeyId!);

                    //Push changes to the database
                    await user.ReleaseAsync(entity.EventCancellation);

                    webm.Result = $"Successfully removed key {req.DeleteKeyId}";
                    webm.Success = true;
                    break;

                case "disable":

                    user.OtpDisable();

                    //Push changes to database
                    await user.ReleaseAsync(entity.EventCancellation);

                    webm.Result = "Successfully disabled OTP";
                    webm.Success = true;

                    break;
            }

            return webm;
        }

        private static bool IsPasswordProtected(OtpRequestMessage req)
        {
            //Currently all actions are password protected
            return req.Action switch
            {
                _ => true
            };
        }

        private async Task<bool> VerifyPasswordAsync(IUser user, OtpRequestMessage req, WebMessage webm, CancellationToken cancellation)
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

            return !webm.Assert(result > 0, CheckPassword);
        }

        private void AddPublicKey(IUser user, WebMessage webm, OtpAuthPublicKey pubkey)
        {
            //The public key object is already validated by the request validator

            if (webm.Assert(user.OtpCanAddKey(), "You cannot add any more otp keys to your account"))
            {
                return;
            }

            try
            {
                //Try to get the ECDA instance to confirm the key data could be recovered properly
                using ECDsa? testAlg = pubkey.GetECDsaPublicKey();

                if (webm.Assert(testAlg != null, "Your JWK is not valid"))
                {
                    return;
                }

                user.OtpAddPublicKey(pubkey);

                webm.Success = true;
                webm.Result = "Successfully added key";
            }
            catch (Exception ex)
            {
                _log.Debug(ex);
                webm.Result = "Your JWK is not valid";
            }
        }

        private sealed class UserGetResult
        {
            [JsonPropertyName("keys")]
            public OtpAuthPublicKey[]? Keys { get; set; }

            [JsonPropertyName("can_add_keys")]
            public bool CanAddKeys { get; set; }

            [JsonPropertyName("data_size")]
            public int? DataSize { get; set; }

            [JsonPropertyName("max_size")]
            public int? MaxSize { get; set; }
        }

        private sealed class OtpRequestMessage() : PrivateStringManager(1)
        {
            [JsonPropertyName("password")]
            public string? Password
            {
                get => this[0];
                set => this[0] = value;
            }

            [JsonPropertyName("action")]
            public string? Action { get; set; }

            [JsonPropertyName("delete_id")]
            public string? DeleteKeyId { get; set; }

            [JsonPropertyName("public_key")]
            public OtpAuthPublicKey? AddKey { get; set; }
        }

        private sealed class OtpMessageValidator : AbstractValidator<OtpRequestMessage>
        {
            public OtpMessageValidator()
            {
                RuleFor(p => p.Action!)
                    .NotEmpty()
                    .WithMessage("Action must be provided")
                    .Matches(@"^(add_key|remove_key|disable)$");

                //Standard resource exhuastion protection (large passwords take time to hash)
                RuleFor(p => p.Password)
                    .MaximumLength(200);

                RuleFor(p => p.AddKey!)
                    .NotNull()
                    .When(p => p.Action == "add_key")   //Key must not be null when the add_key action is used
                    .SetValidator(new OtpPublicKeyValidator())
                    .When(p => p.AddKey is not null);
            }
        }

        internal sealed class OtpPublicKeyValidator : AbstractValidator<OtpAuthPublicKey>
        {
            public OtpPublicKeyValidator()
            {
                RuleFor(a => a.KeyType)
                    .NotEmpty()
                    .Must(kt => "EC".Equals(kt, StringComparison.Ordinal))
                    .WithMessage("The supplied key is not an EC curve key");

                RuleFor(a => a.Curve)
                    .NotEmpty()
                    .WithName("crv")
                    .Must(p => AllowedCurves.Contains(p, StringComparer.Ordinal))
                    .WithMessage("Your key's curve is not supported");

                RuleFor(c => c.KeyId)
                    .NotEmpty()
                    .Length(10, 100)
                    .IllegalCharacters();

                RuleFor(a => a.Algorithm)
                    .NotEmpty()
                    .WithName("alg")
                    .Must(a => AllowedAlgs.Contains(a, StringComparer.Ordinal))
                    .WithMessage("Your key's signature algorithm is not supported");

                //Confirm the x axis parameter is valid
                RuleFor(a => a.X)
                    .NotEmpty()
                    .WithName("x")
                    .Length(10, 200)
                    .WithMessage("Your key's X EC point public key parameter is not valid")
                    .IllegalCharacters()
                    .WithMessage("Your key's X EC point public key parameter conatins invaid characters");

                //Confirm the y axis point is valid
                RuleFor(a => a.Y)
                    .NotEmpty()
                    .WithName("y")
                    .Length(10, 200)
                    .WithMessage("Your key's Y EC point public key parameter is not valid")
                    .IllegalCharacters()
                    .WithMessage("Your key's Y EC point public key parameter conatins invaid characters");
            }
        }
    }
}
