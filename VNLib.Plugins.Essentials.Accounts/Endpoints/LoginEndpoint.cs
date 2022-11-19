/*
* Copyright (c) 2022 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: LoginEndpoint.cs 
*
* LoginEndpoint.cs is part of VNLib.Plugins.Essentials.Accounts which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Accounts is free software: you can redistribute it and/or modify 
* it under the terms of the GNU General Public License as published
* by the Free Software Foundation, either version 2 of the License,
* or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Accounts is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
* General Public License for more details.
*
* You should have received a copy of the GNU General Public License 
* along with VNLib.Plugins.Essentials.Accounts. If not, see http://www.gnu.org/licenses/.
*/

using System;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text.Json.Serialization;

using VNLib.Hashing;
using VNLib.Utils;
using VNLib.Utils.Memory;
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
using static VNLib.Plugins.Essentials.Accounts.AccountManager;


namespace VNLib.Plugins.Essentials.Accounts.Endpoints
{

    /// <summary>
    /// Provides an authentication endpoint for user-accounts
    /// </summary>
    [ConfigurationName("login_endpoint")]
    internal sealed class LoginEndpoint : UnprotectedWebEndpoint
    {
        public const string INVALID_MESSAGE = "Please check your email or password.";
        public const string LOCKED_ACCOUNT_MESSAGE = "You have been timed out, please try again later";
        public const string MFA_ERROR_MESSAGE = "Invalid or expired request.";

        private static readonly LoginMessageValidation LmValidator = new();
       
        private readonly PasswordHashing Passwords;
        private readonly MFAConfig? MultiFactor;
        private readonly IUserManager Users;
        private readonly uint MaxFailedLogins;
        private readonly TimeSpan FailedCountTimeout;

        ///<inheritdoc/>
        protected override ProtectionSettings EndpointProtectionSettings { get; } = new();

        public LoginEndpoint(PluginBase pbase, IReadOnlyDictionary<string, JsonElement> config)
        {
            string? path = config["path"].GetString();
            FailedCountTimeout = config["failed_count_timeout_sec"].GetTimeSpan(TimeParseType.Seconds);
            MaxFailedLogins = config["failed_count_max"].GetUInt32();

            InitPathAndLog(path, pbase.Log);

            Passwords = pbase.GetPasswords();
            Users = pbase.GetUserManager();
            MultiFactor = pbase.GetMfaConfig();
        }

        private class MfaUpgradeWebm : ValErrWebMessage
        {
            [JsonPropertyName("pwtoken")]
            public string? PasswordToken { get; set; }

            [JsonPropertyName("mfa")]
            public bool? MultiFactorUpgrade { get; set; } = null;
        }


        protected async override ValueTask<VfReturnType> PostAsync(HttpEntity entity)
        {
            //Conflict if user is logged in
            if (entity.LoginCookieMatches() || entity.TokenMatches())
            {
                entity.CloseResponse(HttpStatusCode.Conflict);
                return VfReturnType.VirtualSkip;
            }
            
            //If mfa is enabled, allow processing via mfa
            if (MultiFactor != null)
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
                    entity.CloseResponseJson(HttpStatusCode.BadRequest, webm);
                    return VfReturnType.VirtualSkip;
                }
                
                //validate the message
                if (!LmValidator.Validate(loginMessage, webm))
                {
                    entity.CloseResponseJson(HttpStatusCode.UnprocessableEntity, webm);
                    return VfReturnType.VirtualSkip;
                }
                
                //Time to get the user
                using IUser? user = await Users.GetUserAndPassFromEmailAsync(loginMessage.UserName);
                //Make sure account exists
                if (webm.Assert(user != null, INVALID_MESSAGE))
                {
                    entity.CloseResponse(webm);
                    return VfReturnType.VirtualSkip;
                }
                
                //Make sure the account has not been locked out
                if (webm.Assert(!UserLoginLocked(user), LOCKED_ACCOUNT_MESSAGE))
                {
                    goto Cleanup;
                }
                
                //Only allow local accounts
                if (user.IsLocalAccount() && !PrivateString.IsNullOrEmpty(user.PassHash))
                {
                    //If login return true, the response has been set and we should return
                    if (LoginUser(entity, loginMessage, user, webm))
                    {
                        goto Cleanup;
                    }
                }

                //Inc failed login count
                user.FailedLoginIncrement();
                webm.Result = INVALID_MESSAGE;

            Cleanup:
                await user.ReleaseAsync();
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }
            catch (UserUpdateException uue)
            {
                Log.Warn(uue);
                return VfReturnType.Error;
            }
        }
        
        private bool LoginUser(HttpEntity entity, LoginMessage loginMessage, IUser user, MfaUpgradeWebm webm)
        {
            //Verify password before we tell the user the status of their account for security reasons
            if (!Passwords.Verify(user.PassHash, new PrivateString(loginMessage.Password, false)))
            {
                return false;
            }
            //Reset flc for account
            user.FailedLoginCount(0);
            try
            {
                switch (user.Status)
                {
                    case UserStatus.Active:
                        {
                            //Is the account restricted to a local network connection?
                            if (user.LocalOnly && !entity.IsLocalConnection)
                            {
                                Log.Information("User {uid} attempted a login from a non-local network with the correct password. Access was denied", user.UserID);
                                return false;
                            }
                            //Gen and store the pw secret
                            byte[] pwSecret = entity.Session.GenPasswordChallenge(new(loginMessage.Password, false));
                            //Encrypt and convert to base64
                            string clientPwSecret = EncryptSecret(loginMessage.ClientPublicKey, pwSecret);
                            //get the new upgrade jwt string
                            Tuple<string,string>? message = user.MFAGetUpgradeIfEnabled(MultiFactor, loginMessage, clientPwSecret);
                            //if message is null, mfa was not enabled or could not be prepared
                            if (message != null)
                            {
                                //Store the base64 signature
                                entity.Session.MfaUpgradeSignature(message.Item2);
                                //send challenge message to client
                                webm.Result = message.Item1;
                                webm.Success = true;
                                webm.MultiFactorUpgrade = true;
                                break;
                            }
                            //Set password token
                            webm.PasswordToken = clientPwSecret;
                            //Elevate the login status of the session to reflect the user's status
                            webm.Token = entity.GenerateAuthorization(loginMessage, user);
                            //Send the Username (since they already have it)
                            webm.Result = new AccountData()
                            {
                                EmailAddress = user.EmailAddress,
                            };
                            webm.Success = true;
                            //Write to log
                            Log.Verbose("Successful login for user {uid}...", user.UserID[..8]);
                        }
                        break;
                    default:
                        //This is an unhandled case, and should never happen, but just incase write a warning to the log
                        Log.Warn("Account {uid} has invalid status key and a login was attempted from {ip}", user.UserID, entity.TrustedRemoteIp);
                        return false;
                }
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
            return true;
        }
       

        private async ValueTask<VfReturnType> ProcessMfaAsync(HttpEntity entity)
        {
            MfaUpgradeWebm webm = new();
            //Recover request message
            using JsonDocument? request = await entity.GetJsonFromFileAsync();
            if (webm.Assert(request != null, "Invalid request data"))
            {
                entity.CloseResponseJson(HttpStatusCode.BadRequest, webm);
                return VfReturnType.VirtualSkip;
            }
            //Recover upgrade jwt
            string? upgradeJwt = request.RootElement.GetPropString("upgrade");
            if (webm.Assert(upgradeJwt != null, "Missing required upgrade data"))
            {
                entity.CloseResponseJson(HttpStatusCode.UnprocessableEntity, webm);
                return VfReturnType.VirtualSkip;
            }
            
            //Recover stored signature
            string? storedSig = entity.Session.MfaUpgradeSignature();
            if(webm.Assert(!string.IsNullOrWhiteSpace(storedSig), MFA_ERROR_MESSAGE))
            {
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }
            
            //Recover upgrade data from upgrade message
            if (!MultiFactor!.RecoverUpgrade(upgradeJwt, storedSig, out MFAUpgrade? upgrade))
            {
                webm.Result = MFA_ERROR_MESSAGE;
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }
            
            //recover user account 
            using IUser? user = await Users.GetUserFromEmailAsync(upgrade.UserName!);

            if (webm.Assert(user != null, MFA_ERROR_MESSAGE))
            {
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }

            //Wipe session signature
            entity.Session.MfaUpgradeSignature(null);

            //Make sure the account has not been locked out
            if (!webm.Assert(!UserLoginLocked(user), LOCKED_ACCOUNT_MESSAGE))
            {
                //process mfa login
                LoginMfa(entity, user, request, upgrade, webm);
            }
      
            //Update user on clean process
            await user.ReleaseAsync();
            //Close rseponse
            entity.CloseResponse(webm);
            return VfReturnType.VirtualSkip;
        }

        private void LoginMfa(HttpEntity entity, IUser user, JsonDocument request, MFAUpgrade upgrade, MfaUpgradeWebm webm)
        {         
            //Recover the user's local time
            DateTimeOffset localTime = request.RootElement.GetProperty("localtime").GetDateTimeOffset();

            //Check mode
            switch (upgrade.Type)
            {
                case MFAType.TOTP:
                    {
                        //get totp code from request
                        uint code = request.RootElement.GetProperty("code").GetUInt32();
                        //Verify totp code
                        if (!MultiFactor!.VerifyTOTP(user, code))
                        {
                            webm.Result = "Please check your code.";
                            //Increment flc and update the user in the store
                            user.FailedLoginIncrement();                           
                            return;
                        }
                        //Valid, complete                         
                    }
                    break;
                case MFAType.GPG:
                    { }
                    break;
                default:
                    {
                        webm.Result = MFA_ERROR_MESSAGE;
                    }
                    return;
            }
            //build login message from upgrade
            LoginMessage loginMessage = new()
            {
                ClientID = upgrade.ClientID,
                ClientPublicKey = upgrade.Base64PubKey,
                LocalLanguage = upgrade.ClientLocalLanguage,
                LocalTime = localTime,
                UserName = upgrade.UserName
            };
            //Elevate the login status of the session to reflect the user's status
            webm.Token = entity.GenerateAuthorization(loginMessage, user);
            //Set the password token as the password field of the login message
            webm.PasswordToken = upgrade.PwClientData;
            //Send the Username (since they already have it)
            webm.Result = new AccountData()
            {
                EmailAddress = user.EmailAddress,
            };
            webm.Success = true;
            //Write to log
            Log.Verbose("Successful login for user {uid}...", user.UserID[..8]);
        }        

        private static string EncryptSecret(string pubKey, byte[] secret)
        {
            //Alloc buffer for secret
            using IMemoryHandle<byte> buffer = Memory.SafeAlloc<byte>(4096);
            //Try to encrypt the data
            ERRNO count = TryEncryptClientData(pubKey, secret, buffer.Span);
            //Clear secret
            RandomHash.GetRandomBytes(secret);
            //Convert to base64 string
            return Convert.ToBase64String(buffer.Span[..(int)count]);
        }

        public bool UserLoginLocked(IUser user)
        {
            //Recover last counter value
            TimestampedCounter flc = user.FailedLoginCount();
            if(flc.Count < MaxFailedLogins)
            {
                //Period exceeded
                return false;
            }
            //See if the flc timeout period has expired
            if (flc.LastModified.Add(FailedCountTimeout) < DateTimeOffset.UtcNow)
            {
                //clear flc flag
                user.FailedLoginCount(0);
                return false;
            }
            //Count has been exceeded, and has not timed out yet
            return true;
        }
    }
}