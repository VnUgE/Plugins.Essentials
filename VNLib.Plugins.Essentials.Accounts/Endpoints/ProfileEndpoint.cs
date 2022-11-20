/*
* Copyright (c) 2022 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: ProfileEndpoint.cs 
*
* ProfileEndpoint.cs is part of VNLib.Plugins.Essentials.Accounts which is part of the larger 
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

using VNLib.Utils.Logging;
using VNLib.Plugins.Essentials.Users;
using VNLib.Plugins.Essentials.Endpoints;
using VNLib.Plugins.Essentials.Extensions;
using VNLib.Plugins.Extensions.Validation;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Users;
using static VNLib.Plugins.Essentials.Statics;


namespace VNLib.Plugins.Essentials.Accounts.Endpoints
{
    /// <summary>
    /// Provides an http endpoint for user account profile access
    /// </summary>
    [ConfigurationName("profile_endpoint")]
    internal sealed class ProfileEndpoint : ProtectedWebEndpoint
    {
        private readonly IUserManager Users;
        
        public ProfileEndpoint(PluginBase pbase, IReadOnlyDictionary<string, JsonElement> config)
        {
            string? path = config["path"].GetString();
            
            InitPathAndLog(path, pbase.Log);
            //Store user system
            Users = pbase.GetUserManager();
        }

        protected override async ValueTask<VfReturnType> GetAsync(HttpEntity entity)
        {
            //get user data from database
            using IUser? user = await Users.GetUserFromIDAsync(entity.Session.UserID);
            //Make sure the account exists
            if (user == null || user.Status != UserStatus.Active)
            {
                //Account was not found
                entity.CloseResponse(HttpStatusCode.NotFound);
                return VfReturnType.VirtualSkip;
            }
            //Get the stored profile
            AccountData? profile = user.GetProfile();
            //No profile found, so return an empty "profile"
            profile ??= new()
            {
                //set email address
                EmailAddress = user.EmailAddress,
                //created time in rfc1123 gmt time
                Created = user.Created.ToString("R")
            };
            //Serialize the profile and return to user
            entity.CloseResponseJson(HttpStatusCode.OK, profile);
            return VfReturnType.VirtualSkip;
        }
        protected override async ValueTask<VfReturnType> PostAsync(HttpEntity entity)
        {
            ValErrWebMessage webm = new();
            try
            {
                //Recover the update message form the client
                AccountData? updateMessage = await entity.GetJsonFromFileAsync<AccountData>(SR_OPTIONS);
                if (webm.Assert(updateMessage != null, "Malformatted payload"))
                {
                    entity.CloseResponseJson(HttpStatusCode.BadRequest, webm);
                    return VfReturnType.VirtualSkip;
                }
                //Validate the new account data
                if (!AccountValidations.AccountDataValidator.Validate(updateMessage, webm))
                {
                    entity.CloseResponseJson(HttpStatusCode.UnprocessableEntity, webm);
                    return VfReturnType.VirtualSkip;
                }
                //Get the user from database
                using IUser? user = await Users.GetUserFromIDAsync(entity.Session.UserID);
                //Make sure the user exists
                if (webm.Assert(user != null, "Account does not exist"))
                {
                    //Should probably log the user out here
                    entity.CloseResponseJson(HttpStatusCode.NotFound, webm);
                    return VfReturnType.VirtualSkip;
                }
                //Overwite the current profile data (will also sanitize inputs)
                user.SetProfile(updateMessage);
                //Update the user only if successful
                await user.ReleaseAsync();
                webm.Result = "Successfully updated account";
                webm.Success = true;
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }
            //Catch an account update exception
            catch (UserUpdateException uue)
            {
                Log.Error(uue, "An error occured while the user account is being updated");
                //Return message to client
                webm.Result = "An error occured while updating your account, try again later";
                entity.CloseResponseJson(HttpStatusCode.InternalServerError, webm);
                return VfReturnType.VirtualSkip;
            }
        }
    }
}