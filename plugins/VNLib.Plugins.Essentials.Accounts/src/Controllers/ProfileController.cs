/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: ProfileController.cs 
*
* ProfileController.cs is part of VNLib.Plugins.Essentials.Accounts which 
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

using System.Net;
using System.Text.Json;
using System.Threading.Tasks;

using FluentValidation;

using VNLib.Utils.Logging;
using VNLib.Plugins.Essentials.Users;
using VNLib.Plugins.Essentials.Extensions;
using VNLib.Plugins.Extensions.Validation;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Users;
using static VNLib.Plugins.Essentials.Statics;

using VNLib.Plugins.Essentials.Accounts.AccountRpc;

namespace VNLib.Plugins.Essentials.Accounts.Controllers
{
    internal sealed class ProfileController(PluginBase plugin) : IAccountRpcController
    {
        private readonly UserManager _users = plugin.GetOrCreateSingleton<UserManager>();
        private readonly ILogProvider _log = plugin.Log.CreateScope("Profile RPC");

        ///<inheritdoc/>
        public IAccountRpcMethod[] GetMethods()
        {
            return [
                new AccountGetMethod(_users),
                new AccountUpdateMethod(_users, _log)
            ];
        }

        private sealed class AccountGetMethod(IUserManager Users) : IAccountRpcMethod
        {
            ///<inheritdoc/>
            public string MethodName => "profile.get";

            /// <inheritdoc/>
            public RpcMethodOptions Flags => RpcMethodOptions.AuthRequired;

            ///<inheritdoc/>
            public ValueTask<object?> OnUserGetAsync(HttpEntity entity) => default;

            ///<inheritdoc/>
            public async ValueTask<RpcCommandResult> InvokeAsync(HttpEntity entity, AccountJRpcRequest req, JsonElement args)
            {
                using IUser? user = await Users.GetUserFromIDAsync(entity.Session.UserID);

                if (user == null || user.Status != UserStatus.Active)
                {
                    //Account was not found
                    return RpcCommandResult.Error(HttpStatusCode.NotFound);
                }

                AccountData? profile = user.GetProfile();

                //No profile found, so return an empty "profile"
                profile ??= new();

                profile.EmailAddress = user.EmailAddress;
                profile.Created = user.Created.ToString("R");

                //Serialize the profile and return to user
                return RpcCommandResult.Okay(profile);
            }
        }

        private sealed class AccountUpdateMethod(IUserManager Users, ILogProvider Log) : IAccountRpcMethod
        {
            ///<inheritdoc/>
            public string MethodName => "profile.update";

            /// <inheritdoc/>
            public RpcMethodOptions Flags => RpcMethodOptions.AuthRequired;

            ///<inheritdoc/>
            public ValueTask<object?> OnUserGetAsync(HttpEntity entity) => default;

            ///<inheritdoc/>
            public async ValueTask<RpcCommandResult> InvokeAsync(HttpEntity entity, AccountJRpcRequest _, JsonElement args)
            {
                WebMessage webm = new();
                try
                {
                    if (args.ValueKind != JsonValueKind.Object)
                    {
                        return RpcCommandResult.Error(HttpStatusCode.BadRequest);
                    }

                    //Recover the update message form the client
                    AccountData? updateMessage = args.Deserialize<AccountData>(SR_OPTIONS);
                    if (webm.Assert(updateMessage != null, "Malformatted payload"))
                    {
                        return RpcCommandResult.Error(HttpStatusCode.BadRequest);
                    }

                    //Validate the new account data
                    if (!AccountValidations.AccountDataValidator.Validate(updateMessage, webm))
                    {
                        return RpcCommandResult.Error(HttpStatusCode.UnprocessableEntity, webm);
                    }

                    //Get the user from database
                    using IUser? user = await Users.GetUserFromIDAsync(entity.Session.UserID, entity.EventCancellation);

                    //Make sure the user exists
                    if (webm.Assert(user != null, "Account does not exist"))
                    {
                        //Should probably log the user out here
                        return RpcCommandResult.Error(HttpStatusCode.NotFound, webm);
                    }

                    //Clear internal fields.
                    updateMessage.EmailAddress = null;
                    updateMessage.Created = null;

                    user.SetProfile(updateMessage);

                    //Update the user only if successful
                    await user.ReleaseAsync();

                    webm.Result = "Successfully updated account";
                    webm.Success = true;

                    return RpcCommandResult.Okay(webm);
                }
                //Catch an account update exception
                catch (UserUpdateException uue)
                {
                    Log.Error(uue, "An error occured while the user account is being updated");

                    //Return message to client
                    webm.Result = "An error occured while updating your account, try again later";
                    return RpcCommandResult.Error(HttpStatusCode.InternalServerError, webm);
                }
            }
        }

    }
}