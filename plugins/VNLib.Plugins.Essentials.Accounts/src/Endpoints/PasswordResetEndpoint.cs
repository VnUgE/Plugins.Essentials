/*
* Copyright (c) 2024 Vaughn Nugent
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

using VNLib.Utils;
using VNLib.Utils.Memory;
using VNLib.Plugins.Essentials.Users;
using VNLib.Plugins.Essentials.Extensions;
using VNLib.Plugins.Essentials.Endpoints;
using VNLib.Plugins.Essentials.Accounts.MFA;
using VNLib.Plugins.Extensions.Validation;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Users;
using VNLib.Plugins.Extensions.Loading.Routing;
using VNLib.Plugins.Essentials.Accounts.MFA.Totp;

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
    [EndpointPath("{{path}}")]
    [ConfigurationName("password_endpoint")]
    internal sealed class PasswordChangeEndpoint(PluginBase pbase, IConfigScope config) : ProtectedWebEndpoint
    {
        private readonly IValidator<PasswordResetMesage> ResetMessValidator = GetMessageValidator();
        private readonly UserManager Users = pbase.GetOrCreateSingleton<UserManager>();
        private readonly MfaAuthManager _mfaAuth = pbase.GetOrCreateSingleton<MfaAuthManager>();


        protected override async ValueTask<VfReturnType> PostAsync(HttpEntity entity)
        {
            ValErrWebMessage webm = new();

            //get the request body
            using PasswordResetMesage? pwReset = await entity.GetJsonFromFileAsync<PasswordResetMesage>();

            if (webm.Assert(pwReset != null, "No request specified"))
            {
                return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
            }

            //Validate
            if(!ResetMessValidator.Validate(pwReset, webm))
            {
                return VirtualOk(entity, webm);
            }

            //get the user's entry in the table
            using IUser? user = await Users.GetUserFromIDAsync(entity.Session.UserID, entity.EventCancellation);

            if(webm.Assert(user != null, "An error has occured, please log-out and try again"))
            {
                return VirtualOk(entity, webm);
            }

            //Make sure the account's origin is a local profile
            if (webm.Assert(user.IsLocalAccount(), "External accounts cannot be modified"))
            {
                return VirtualOk(entity, webm);
            }

            //Validate the user's current password
            ERRNO isPassValid = await Users.ValidatePasswordAsync(user, pwReset.Current!, PassValidateFlags.None, entity.EventCancellation);

            //Verify the user's old password
            if (webm.Assert(isPassValid > 0, "Please check your current password"))
            {
                return VirtualOk(entity, webm);
            }

            //Check if totp is enabled
            if (_mfaAuth.TotpIsEnabled() && user.TotpEnabled())
            {
                //TOTP code is required
                if (webm.Assert(pwReset.TotpCode.HasValue, "TOTP is enabled on this user account, you must enter your TOTP code."))
                {
                    return VirtualOk(entity, webm);
                }

                //Veriy totp code
                bool verified = _mfaAuth.TotpVerifyCode(user, pwReset.TotpCode.Value);

                if (webm.Assert(verified, "Please check your TOTP code and try again"))
                {
                    return VirtualOk(entity, webm);
                }

                //continue
            }

            //Update the user's password
            if (await Users.UpdatePasswordAsync(user, pwReset.NewPassword!, entity.EventCancellation) == 1)
            {
                //error
                webm.Result = "Your password could not be updated";
                return VirtualOk(entity, webm);
            }

            //Publish to user database
            await user.ReleaseAsync(entity.EventCancellation);

            //delete the user's MFA entry so they can re-enable it
            webm.Result = "Your password has been updated";
            webm.Success = true;
            return VirtualOk(entity, webm);
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
                .SetValidator(AccountValidations.PasswordValidator);

            return rules;
        }

        private sealed class PasswordResetMesage() : PrivateStringManager(2)
        {
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
