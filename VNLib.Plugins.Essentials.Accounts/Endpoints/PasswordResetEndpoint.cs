/*
* Copyright (c) 2022 Vaughn Nugent
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
using System.Text.Json;
using System.Threading.Tasks;
using System.Collections.Generic;

using FluentValidation;

using VNLib.Utils.Memory;
using VNLib.Utils.Extensions;
using VNLib.Plugins.Essentials.Users;
using VNLib.Plugins.Essentials.Extensions;
using VNLib.Plugins.Extensions.Validation;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Users;
using VNLib.Plugins.Essentials.Endpoints;

namespace VNLib.Plugins.Essentials.Accounts.Endpoints
{

    /// <summary>
    /// Password reset for user's that are logged in and know 
    /// their passwords to reset their MFA methods
    /// </summary>
    [ConfigurationName("password_endpoint")]
    internal sealed class PasswordChangeEndpoint : ProtectedWebEndpoint
    {
        private readonly IUserManager Users;
        private readonly PasswordHashing Passwords;

        public PasswordChangeEndpoint(PluginBase pbase, IReadOnlyDictionary<string, JsonElement> config)
        {
            string? path = config["path"].GetString();
            InitPathAndLog(path, pbase.Log);

            Users = pbase.GetUserManager();
            Passwords = pbase.GetPasswords();
        }

        protected override async ValueTask<VfReturnType> PostAsync(HttpEntity entity)
        {
            ValErrWebMessage webm = new();
            //get the request body
            using JsonDocument? request = await entity.GetJsonFromFileAsync();
            if (request == null)
            {
                webm.Result = "No request specified";
                entity.CloseResponseJson(HttpStatusCode.BadRequest, webm);
                return VfReturnType.VirtualSkip;
            }
            //get the user's old password
            using PrivateString? currentPass = (PrivateString?)request.RootElement.GetPropString("current");
            //Get password as a private string
            using PrivateString? newPass = (PrivateString?)request.RootElement.GetPropString("new_password");
            if (PrivateString.IsNullOrEmpty(currentPass))
            {
                webm.Result = "You must specifiy your current password.";
                entity.CloseResponseJson(HttpStatusCode.UnprocessableEntity, webm);
                return VfReturnType.VirtualSkip;
            }
            if (PrivateString.IsNullOrEmpty(newPass))
            {
                webm.Result = "You must specifiy a new password.";
                entity.CloseResponseJson(HttpStatusCode.UnprocessableEntity, webm);
                return VfReturnType.VirtualSkip;
            }
            //Test the password against minimum
            if (!AccountValidations.PasswordValidator.Validate((string)newPass, webm))
            {
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }
            if (webm.Assert(!currentPass.Equals(newPass), "Passwords cannot be the same."))
            {
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }
            //get the user's entry in the table
            using IUser?  user = await Users.GetUserAndPassFromIDAsync(entity.Session.UserID);
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
            if (!Passwords.Verify(user.PassHash, currentPass))
            {
                webm.Result = "Please check your current password";
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }
            //Hash the user's new password
            using PrivateString newPassHash = Passwords.Hash(newPass);
            //Update the user's password
            if (!await Users.UpdatePassAsync(user, newPassHash))
            {
                //error
                webm.Result = "Your password could not be updated";
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }
            await user.ReleaseAsync();
            //delete the user's MFA entry so they can re-enable it
            webm.Result = "Your password has been updated";
            webm.Success = true;
            entity.CloseResponse(webm);
            return VfReturnType.VirtualSkip;
        }
    }
}
