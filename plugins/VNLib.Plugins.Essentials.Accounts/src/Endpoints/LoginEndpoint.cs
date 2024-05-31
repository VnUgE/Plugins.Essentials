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
using System.Net;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text.Json.Serialization;

using FluentValidation;

using VNLib.Utils;
using VNLib.Utils.Logging;
using VNLib.Utils.Extensions;
using VNLib.Plugins.Essentials.Users;
using VNLib.Plugins.Essentials.Endpoints;
using VNLib.Plugins.Essentials.Extensions;
using VNLib.Plugins.Extensions.Validation;
using VNLib.Plugins.Essentials.Accounts.MFA;
using VNLib.Plugins.Essentials.Accounts.Validators;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Users;
using static VNLib.Plugins.Essentials.Statics;
using VNLib.Plugins.Essentials.Accounts.MFA.Totp;
using VNLib.Plugins.Essentials.Accounts.MFA.Fido;


/*
  * Password only log-ins should be immune to repeat attacks on the same backend, because sessions are 
  * guarunteed to be mutally exclusive on the same system, therefor a successful login cannot be repeated
  * without a logout with the proper authorization.
  * 
  * Since MFA upgrades are indempodent upgrades can be regenerated continually as long as the session 
  * is not authorized, however login authorizations should be immune to repeats because session locking
  * 
  * Session id's are also regenerated per request, the only possible vector could be stale session cache
  * that has a valid MFA key and an old, but valid session id.
  */

namespace VNLib.Plugins.Essentials.Accounts.Endpoints
{

    /// <summary>
    /// Provides an authentication endpoint for user-accounts
    /// </summary>
    [ConfigurationName("login_endpoint")]
    internal sealed class LoginEndpoint : UnprotectedWebEndpoint
    {
        public const string INVALID_MESSAGE = "Please check your email or password. You may get locked out.";
        public const string LOCKED_ACCOUNT_MESSAGE = "You have been timed out, please try again later";
        public const string MFA_ERROR_MESSAGE = "Invalid or expired request.";

        private static readonly LoginMessageValidation LmValidator = new();
        
        private readonly MfaAuthManager MultiFactor;
        private readonly IUserManager Users;
        private readonly FailedLoginLockout _lockout;

        public LoginEndpoint(PluginBase pbase, IConfigScope config)
        {
            string path = config.GetRequiredProperty("path", p => p.GetString()!);
            TimeSpan duration = config["failed_attempt_timeout_sec"].GetTimeSpan(TimeParseType.Seconds);
            uint maxLogins = config["max_login_attempts"].GetUInt32();

            InitPathAndLog(path, pbase.Log);

            MFAConfig conf = pbase.GetConfigElement<MFAConfig>();
            Users = pbase.GetOrCreateSingleton<UserManager>();
            _lockout = new(maxLogins, duration);
            

            List<IMfaProcessor> proc = [];

            if(conf.TOTPEnabled)
            {
                proc.Add(new TotpAuthProcessor(conf.TOTPConfig!));
            }

            if(conf.FIDOEnabled)
            {
                proc.Add(new FidoMfaProcessor(conf.FIDOConfig!));
            }

            MultiFactor = new(conf, [.. proc]);
        }

        protected override ERRNO PreProccess(HttpEntity entity)
        {
            //Cannot have new sessions
            return base.PreProccess(entity) && !entity.Session.IsNew;
        }

        protected async override ValueTask<VfReturnType> PostAsync(HttpEntity entity)
        {
            //Conflict if user is logged in
            if (entity.IsClientAuthorized(AuthorzationCheckLevel.Any))
            {
                return VirtualClose(entity, HttpStatusCode.Conflict);
            }
            
            /*
             * To continue an mfa upgrade, the client must send
             * an mfa query argument to continue the upgrade process
             */
            if (MultiFactor.Armed)
            {
                if (entity.QueryArgs.ContainsKey("mfa"))
                {
                    return await ProcessMfaAsync(entity);
                }
            }

            return await ProccesLoginAsync(entity);
        }

        private async ValueTask<VfReturnType> ProccesLoginAsync(HttpEntity entity)
        {
            MfaUpgradeWebm webm = new();
            try
            {
                //Make sure the id is regenerated (or upgraded if successful login)
                entity.Session.RegenID();
                
                using LoginMessage? loginMessage = await entity.GetJsonFromFileAsync<LoginMessage>(SR_OPTIONS);
                
                if (webm.Assert(loginMessage != null, "Invalid request data"))
                {
                    return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
                }
                
                //validate the message
                if (!LmValidator.Validate(loginMessage, webm))
                {
                    return VirtualClose(entity, webm, HttpStatusCode.UnprocessableEntity);
                }
               
                using IUser? user = await Users.GetUserFromUsernameAsync(loginMessage.UserName);

                //Make sure account exists
                if (webm.Assert(user != null, INVALID_MESSAGE))
                {
                    return VirtualOk(entity, webm);
                }

                bool locked = _lockout.CheckOrClear(user, entity.RequestedTimeUtc);

                //Make sure the account has not been locked out
                if (webm.Assert(locked == false, LOCKED_ACCOUNT_MESSAGE))
                {
                    goto Cleanup;
                }
                
                //Only allow local accounts
                if (!user.IsLocalAccount())
                {
                    goto Failed;
                }

                //Validate password
                if (await ValidatePasswordAsync(user, loginMessage, entity.EventCancellation) == false)
                {
                    goto Failed;
                }

                //If login return true, the response has been set and we should return
                if (LoginOrMfaConnection(entity, loginMessage, user, webm))
                {
                    goto Cleanup;
                }

            Failed:

                //Inc failed login count
                _lockout.Increment(user, entity.RequestedTimeUtc);
                webm.Result = INVALID_MESSAGE;

            Cleanup:
                await user.ReleaseAsync();
                return VirtualOk(entity ,webm);
            }
            catch (UserUpdateException uue)
            {
                Log.Warn(uue);
                return VfReturnType.Error;
            }
        }   
        
        private async Task<bool> ValidatePasswordAsync(IUser user, LoginMessage login, CancellationToken cancellation)
        {
            //Validate password against store
            ERRNO valResult = await Users.ValidatePasswordAsync(user, login.Password!, PassValidateFlags.None, cancellation);
         
            return valResult == UserPassValResult.Success;
        }

        private bool LoginOrMfaConnection(HttpEntity entity, LoginMessage loginMessage, IUser user, MfaUpgradeWebm webm)
        {
            //Only allow active users
            if (user.Status != UserStatus.Active)
            {
                //This is an unhandled case, and should never happen, but just incase write a warning to the log
                Log.Warn("Account {uid} has invalid status key and a login was attempted from {ip}", user.UserID, entity.TrustedRemoteIp);
                return false;
            }

            //Reset flc for account, either the user will be authorized, or the mfa will be triggered, but the flc should be reset
            user.ClearFailedLoginCount();

            try
            {
                /*
                 * Determine if the user uses MFA to guard their account. If so 
                 * force an MFA upgrade before allowing the user to login
                 */
                if (MultiFactor.HasMfaEnabled(user))
                {
                    //the upgrade message
                    webm.Result = MultiFactor.GetChallengeMessage(entity, user, loginMessage);
                    webm.MultiFactorUpgrade = true;
                }
                else
                {
                    /* SUCCESSFULL LOGIN! */

                    //Elevate the login status of the session to reflect the user's status
                    entity.GenerateAuthorization(loginMessage, user, webm);

                    //Send the Username (since they already have it)
                    webm.Result = new AccountData()
                    {
                        EmailAddress = user.EmailAddress,
                    };

                    //Write to log
                    Log.Verbose("Successful login for user {uid}...", user.UserID[..8]);
                }

                webm.Success = true;
                return true;
            }
            /*
             * Account auhorization may throw excetpions if the configuration does not 
             * match the client, or the client sent invalid or malicous data and 
             * it could not grant authorization
             */
            catch (OutOfMemoryException)
            {
                webm.Result = "Your browser sent malformatted security information";
            }
            catch (CryptographicException ce)
            {
                webm.Result = "Your browser sent malformatted security information";
                Log.Debug(ce);
            }
            return false;
        }       

        private async ValueTask<VfReturnType> ProcessMfaAsync(HttpEntity entity)
        {
            MfaUpgradeWebm webm = new();

            //Recover request message
            using JsonDocument? request = await entity.GetJsonFromFileAsync();
            
            if (webm.Assert(request != null, "Invalid request data"))
            {
                return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
            }

            MfaChallenge? upgrade = MultiFactor.GetChallengeData(entity, request);
           
            /*
             * Upgrade may be null if it is not valid, not correctly formatted,
             * expired, and so on. We cannot leak information about the upgrade
             * request to the client, so return a generic error message
             */
            if (webm.Assert(upgrade != null, MFA_ERROR_MESSAGE))
            {
                return VirtualOk(entity, webm);
            }
            
            using IUser? user = await Users.GetUserFromUsernameAsync(upgrade.UserName!);

            if (webm.Assert(user != null, MFA_ERROR_MESSAGE))
            {
                return VirtualOk(entity, webm);
            }

            bool locked = _lockout.CheckOrClear(user, entity.RequestedTimeUtc);
           
            if (webm.Assert(locked == false, LOCKED_ACCOUNT_MESSAGE))
            {
                //Locked, so clear stored signature
                MultiFactor.InvalidateUpgrade(entity);
            }
            else if (MultiFactor.VerifyResponse(entity, upgrade, user, request))
            {
               /*
                * ###################################################
                * 
                *               AUTHORIZATION ZONE
                *               
                *       Connection will be elevated to authorized
                *       this is a successful login!
                * 
                * ####################################################
                */

                MultiFactor.InvalidateUpgrade(entity);

                /*
                 * Time to authorize the user now. This will cause state changs
                 * to the client session, and user account. The user
                 * is now authorized to use the session.
                 */
                entity.GenerateAuthorization(upgrade, user, webm);
           
                webm.Result = new AccountData()
                {
                    EmailAddress = user.EmailAddress,
                };

                webm.Success = true;
              
                Log.Verbose("Successful login for user {uid}...", user.UserID[..8]);
            }
            else
            {
                webm.Result = "Please check your input and try again.";
            }
      
            //Flush any changes to the user store
            await user.ReleaseAsync();

            //Close rseponse
            return VirtualOk(entity, webm);
        }

        private sealed class MfaUpgradeWebm : ValErrWebMessage
        {

            [JsonPropertyName("mfa")]
            public bool? MultiFactorUpgrade { get; set; } = null;
        }
    }
}