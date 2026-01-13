/*
* Copyright (c) 2025 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: PasswordResetController.cs 
*
* PasswordResetController.cs is part of VNLib.Plugins.Essentials.Accounts which 
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
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using System.Text.Json.Serialization;

using FluentValidation;

using VNLib.Utils;
using VNLib.Utils.Memory;
using VNLib.Plugins.Essentials.Users;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Users;
using VNLib.Plugins.Extensions.Validation;
using VNLib.Plugins.Essentials.Accounts.AccountRpc;

namespace VNLib.Plugins.Essentials.Accounts.Controllers
{

    internal sealed class PasswordResetController(PluginBase plugin) : IAccountRpcController
    {
        private readonly IUserManager _users = plugin.GetOrCreateSingleton<UserManager>();

        public IAccountRpcMethod[] GetMethods()
        {
            return [ new PasswordResetRpcMethod(_users) ];
        }

        private sealed class PasswordResetRpcMethod(IUserManager Users) : IAccountRpcMethod
        {
            private readonly PwResetMessageVal _messageValidator = new();

            ///<inheritdoc/>
            public string MethodName => "password.reset";

            ///<inheritdoc/>
            public RpcMethodOptions Flags => RpcMethodOptions.AuthRequired;

            ///<inheritdoc/>
            public ValueTask<object?> OnUserGetAsync(HttpEntity entity) => default;

            ///<inheritdoc/>
            public async ValueTask<RpcCommandResult> InvokeAsync(HttpEntity entity, AccountJRpcRequest message, JsonElement request)
            {
                WebMessage webm = new();

                using PasswordResetMesage? pwReset = request.Deserialize<PasswordResetMesage>();

                if (webm.Assert(pwReset != null, "No request specified"))
                {
                    return RpcCommandResult.Error(HttpStatusCode.BadRequest, webm);
                }

                if (!_messageValidator.Validate(pwReset, webm))
                {
                    return RpcCommandResult.Okay(webm);
                }

                using IUser? user = await Users.GetUserFromIDAsync(
                    entity.Session.UserID,
                    entity.EventCancellation
                );

                if (webm.Assert(user != null, "An error has occured, please log-out and try again"))
                {
                    return RpcCommandResult.Okay(webm);
                }

                //Make sure the account's origin is a local profile
                if (webm.Assert(user.IsLocalAccount(), "External accounts cannot be modified"))
                {
                    return RpcCommandResult.Okay(webm);
                }

                if (webm.Assert(user.Status == UserStatus.Active, "An error has occured, please log-out and try again"))
                {
                    return RpcCommandResult.Okay(webm);
                }

                //Verify existing password
                ERRNO isPassValid = await Users.ValidatePasswordAsync(
                    user,
                    password: pwReset.Current!,
                    flags: PassValidateFlags.None,
                    entity.EventCancellation
                );

                if (webm.Assert(isPassValid == UserPassValResult.Success, "Please check your current password"))
                {
                    return RpcCommandResult.Okay(webm);
                }

                //TODO Enable mfa auth

                ERRNO updateResult = await Users.UpdatePasswordAsync(
                    user,
                    password: pwReset.NewPassword!,
                    hashingProvider: Users.GetHashProvider(),
                    cancellation: entity.EventCancellation
                );

                //Update the user's password
                if (updateResult < 1)
                {
                    webm.Result = "Your password could not be updated";
                    return RpcCommandResult.Okay(webm);
                }

                await user.ReleaseAsync(entity.EventCancellation);

                webm.Result = "Your password has been updated";
                webm.Success = true;
                return RpcCommandResult.Okay(webm);
            }

            private sealed class PwResetMessageVal : AbstractValidator<PasswordResetMesage>
            {
                public PwResetMessageVal()
                {
                    RuleFor(static pw => pw.Current)
                        .NotEmpty()
                        .WithMessage("You must specify your current password")
                        .Length(8, 100);

                    //Use centralized password validator for new passwords
                    RuleFor(static pw => pw.NewPassword)
                         .NotEmpty()
                         .NotEqual(static pm => pm.Current)
                         .WithMessage("Your new password may not equal your current password")
                         .SetValidator(AccountValidations.PasswordValidator);
                }
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
}
