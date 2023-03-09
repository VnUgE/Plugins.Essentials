/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: PasswordResetEndpoint.cs 
*
* PasswordResetEndpoint.cs is part of VNLib.Plugins.Essentials.Accounts which is part of the larger 
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
using System.Net;
using System.Threading.Tasks;
using System.Text.Json.Serialization;

using FluentValidation;

using VNLib.Utils.Memory;
using VNLib.Utils.Extensions;
using VNLib.Plugins.Essentials.Users;
using VNLib.Plugins.Essentials.Extensions;
using VNLib.Plugins.Extensions.Validation;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Users;
using VNLib.Plugins.Essentials.Endpoints;
using VNLib.Plugins.Essentials.Accounts.MFA;


namespace VNLib.Plugins.Essentials.Accounts.Endpoints
{

    /*
     * SECURITY NOTES:
     * 
     * If no MFA configuration is loaded for this plugin, users will
     * be permitted to change passwords without thier 2nd factor. 
     * 
     * This decision was made to allow users with MFA enabled from a previous
     * config to change their passwords rather than deny them the ability.
     */

    /// <summary>
    /// Password reset for user's that are logged in and know 
    /// their passwords to reset their MFA methods
    /// </summary>
    [ConfigurationName("password_endpoint")]
    internal sealed class PasswordChangeEndpoint : ProtectedWebEndpoint
    {
        private readonly IUserManager Users;
        private readonly IPasswordHashingProvider Passwords;
        private readonly MFAConfig? mFAConfig;
        private readonly IValidator<PasswordResetMesage> ResetMessValidator;

        public PasswordChangeEndpoint(PluginBase pbase, IConfigScope config)
        {
            string? path = config["path"].GetString();
            InitPathAndLog(path, pbase.Log);

            Users = pbase.GetOrCreateSingleton<UserManager>();
            Passwords = pbase.GetPasswords();
            ResetMessValidator = GetMessageValidator();
            mFAConfig = pbase.GetConfigElement<MFAConfig>();
        }

        private static IValidator<PasswordResetMesage> GetMessageValidator()
        {
            InlineValidator<PasswordResetMesage> rules = new();

            rules.RuleFor(static pw => pw.Current)
                .NotEmpty()
                .WithMessage("You must specify your current password")
                .Length(8, 100);

            //Use centralized password validator for new passwords
            rules.RuleFor(static pw => pw.NewPassword)
                .NotEmpty()
                .NotEqual(static pm => pm.Current)
                .WithMessage("Your new password may not equal your new current password")
                .SetValidator(AccountValidations.PasswordValidator!);

            return rules;
        }

        /*
         * If mfa config
         */

        protected override async ValueTask<VfReturnType> PostAsync(HttpEntity entity)
        {
            ValErrWebMessage webm = new();
            //get the request body
            using PasswordResetMesage? pwReset = await entity.GetJsonFromFileAsync<PasswordResetMesage>();

            if (webm.Assert(pwReset != null, "No request specified"))
            {
                entity.CloseResponseJson(HttpStatusCode.BadRequest, webm);
                return VfReturnType.VirtualSkip;
            }

            //Validate
            if(!ResetMessValidator.Validate(pwReset, webm))
            {
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }

            //get the user's entry in the table
            using IUser? user = await Users.GetUserAndPassFromIDAsync(entity.Session.UserID);

            if(webm.Assert(user != null, "An error has occured, please log-out and try again"))
            {
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }

            //Make sure the account's origin is a local profile
            if (webm.Assert(user.IsLocalAccount(), "External accounts cannot be modified"))
            {
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }

            //Verify the user's old password
            if (!Passwords.Verify(user.PassHash, pwReset.Current.AsSpan()))
            {
                webm.Result = "Please check your current password";
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }

            //Check if totp is enabled
            if (user.MFATotpEnabled())
            {
                if(mFAConfig != null)
                {
                    //TOTP code is required
                    if(webm.Assert(pwReset.TotpCode.HasValue, "TOTP is enabled on this user account, you must enter your TOTP code."))
                    {
                        entity.CloseResponse(webm);
                        return VfReturnType.VirtualSkip;
                    }

                    //Veriy totp code
                    bool verified = mFAConfig.VerifyTOTP(user, pwReset.TotpCode.Value);

                    if (webm.Assert(verified, "Please check your TOTP code and try again"))
                    {
                        entity.CloseResponse(webm);
                        return VfReturnType.VirtualSkip;
                    }
                }
                //continue
            }

            //Hash the user's new password
            using PrivateString newPassHash = Passwords.Hash(pwReset.NewPassword.AsSpan());

            //Update the user's password
            if (!await Users.UpdatePassAsync(user, newPassHash))
            {
                //error
                webm.Result = "Your password could not be updated";
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }

            //Publish to user database
            await user.ReleaseAsync();

            //delete the user's MFA entry so they can re-enable it
            webm.Result = "Your password has been updated";
            webm.Success = true;
            entity.CloseResponse(webm);
            return VfReturnType.VirtualSkip;
        }

        private sealed class PasswordResetMesage : PrivateStringManager
        {
            public PasswordResetMesage() : base(2)
            {
            }

            [JsonPropertyName("current")]
            public string? Current
            {
                get => this[0];
                set => this[0] = value;
            }

            [JsonPropertyName("new_password")]
            public string? NewPassword
            {
                get => this[1];
                set => this[1] = value;
            }

            [JsonPropertyName("totp_code")]
            public uint? TotpCode { get; set; }
        }
    }
}
