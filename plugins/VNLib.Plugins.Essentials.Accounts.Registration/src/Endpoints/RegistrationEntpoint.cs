/*
* Copyright (c) 2022 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts.Registration
* File: RegistrationEntpoint.cs 
*
* RegistrationEntpoint.cs is part of VNLib.Plugins.Essentials.Accounts.Registration which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Accounts.Registration is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Accounts.Registration is distributed in the hope that it will be useful,
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

using FluentValidation;

using Emails.Transactional.Client;
using Emails.Transactional.Client.Exceptions;

using VNLib.Hashing;
using VNLib.Utils.Memory;
using VNLib.Utils.Logging;
using VNLib.Utils.Extensions;
using VNLib.Hashing.IdentityUtility;
using VNLib.Net.Rest.Client.OAuth2;
using VNLib.Plugins.Essentials.Users;
using VNLib.Plugins.Essentials.Endpoints;
using VNLib.Plugins.Essentials.Extensions;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Sql;
using VNLib.Plugins.Extensions.Loading.Events;
using VNLib.Plugins.Extensions.Loading.Users;
using VNLib.Plugins.Extensions.Validation;
using VNLib.Plugins.Extentions.TransactionalEmail;
using VNLib.Plugins.Essentials.Accounts.Registration.TokenRevocation;
using static VNLib.Plugins.Essentials.Accounts.AccountManager;


namespace VNLib.Plugins.Essentials.Accounts.Registration.Endpoints
{

    [ConfigurationName("registration")]
    internal sealed class RegistrationEntpoint : UnprotectedWebEndpoint, IIntervalScheduleable
    {
        /// <summary>
        /// Generates a CNG random buffer to use as a nonce
        /// </summary>
        private static string EntropyNonce => RandomHash.GetRandomHex(16);

        const string FAILED_AUTH_ERR = "Your registration does not exist, you should try to regisiter again.";
        const string REG_ERR_MESSAGE = "Please check your email inbox.";
       
        private readonly IUserManager Users;
        private readonly IValidator<string> RegJwtValdidator;
        private readonly PasswordHashing Passwords;
        private readonly RevokedTokenStore RevokedTokens;
        private readonly TransactionalEmailConfig Emails;
        private readonly Task<ReadOnlyJsonWebKey> RegSignatureKey;
        private readonly TimeSpan RegExpiresSec;

        /// <summary>
        /// Creates back-end functionality for a "registration" or "sign-up" page that integrates with the <see cref="AccountManager"/> plugin
        /// </summary>
        /// <param name="Path">The path identifier</param>
        /// <exception cref="ArgumentException"></exception>
        public RegistrationEntpoint(PluginBase plugin, IReadOnlyDictionary<string, JsonElement> config)
        {
            string? path = config["path"].GetString();

            InitPathAndLog(path, plugin.Log);

            RegExpiresSec = config["reg_expires_sec"].GetTimeSpan(TimeParseType.Seconds);

            //Init reg jwt validator
            RegJwtValdidator = GetJwtValidator();

            Passwords = plugin.GetPasswords();
            Users = plugin.GetUserManager();
            RevokedTokens = new(plugin.GetContextOptions());
            Emails = plugin.GetEmailConfig();

            //Begin the async op to get the signature key from the vault
            RegSignatureKey = plugin.TryGetSecretAsync("reg_sig_key").ToJsonWebKey(true);

            //Register timeout for cleanup
            plugin.ScheduleInterval(this, TimeSpan.FromSeconds(60));
        }

        private static IValidator<string> GetJwtValidator()
        {
            InlineValidator<string> val = new();

            val.RuleFor(static s => s)
                .NotEmpty()
                //Must contain 2 periods for jwt limitation
                .Must(static s => s.Count(s => s == '.') == 2)
                //Guard length
                .Length(20, 500)
                .IllegalCharacters();
            return val;
        }
        

        protected override async ValueTask<VfReturnType> PostAsync(HttpEntity entity)
        {
            ValErrWebMessage webm = new();
            //Get the json request data from client
            using JsonDocument? request = await entity.GetJsonFromFileAsync();

            if(webm.Assert(request != null, "No request data present"))
            {
                entity.CloseResponseJson(HttpStatusCode.BadRequest, webm);
                return VfReturnType.VirtualSkip;
            }

            //Get the jwt string from client
            string? regJwt = request.RootElement.GetPropString("token");
            using PrivateString? password = (PrivateString?)request.RootElement.GetPropString("password");

            //validate inputs
            {
                if (webm.Assert(regJwt != null, FAILED_AUTH_ERR))
                {
                    entity.CloseResponse(webm);
                    return VfReturnType.VirtualSkip;
                }
                
                if (webm.Assert(password != null, "You must specify a password."))
                {
                    entity.CloseResponse(webm);
                    return VfReturnType.VirtualSkip;
                }
                //validate new password
                if(!AccountValidations.PasswordValidator.Validate((string)password, webm))
                {
                    entity.CloseResponse(webm);
                    return VfReturnType.VirtualSkip;
                }
                //Validate jwt
                if (webm.Assert(RegJwtValdidator.Validate(regJwt).IsValid, FAILED_AUTH_ERR))
                {
                    entity.CloseResponse(webm);
                    return VfReturnType.VirtualSkip;
                }
            }

            //Verify jwt has not been revoked            
            if(await RevokedTokens.IsRevokedAsync(regJwt, entity.EventCancellation))
            {
                webm.Result = FAILED_AUTH_ERR;
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }

            string emailAddress;
            try
            {
                //get jwt
                using JsonWebToken jwt = JsonWebToken.Parse(regJwt);
                //verify signature
                bool verified = jwt.VerifyFromJwk(RegSignatureKey.Result);

                if (webm.Assert(verified, FAILED_AUTH_ERR))
                {
                    entity.CloseResponse(webm);
                    return VfReturnType.VirtualSkip;
                }

                //recover iat and email address
                using JsonDocument reg = jwt.GetPayload();
                emailAddress = reg.RootElement.GetPropString("email")!;
                DateTimeOffset iat = DateTimeOffset.FromUnixTimeSeconds(reg.RootElement.GetProperty("iat").GetInt64());

                //Verify IAT against expiration at second resolution
                if (webm.Assert(iat.Add(RegExpiresSec) > DateTimeOffset.UtcNow, FAILED_AUTH_ERR))
                {
                    entity.CloseResponse(webm);
                    return VfReturnType.VirtualSkip;
                }
            }
            catch (FormatException fe)
            {
                Log.Debug(fe);
                webm.Result = FAILED_AUTH_ERR;
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }
           

            //Always hash the new password, even if failed
            using PrivateString passHash = Passwords.Hash(password);

            try
            {
                //Generate userid from email
                string uid = GetRandomUserId();

                //Create the new user
                using IUser user = await Users.CreateUserAsync(uid, emailAddress, MINIMUM_LEVEL, passHash, entity.EventCancellation);

                //Set active status
                user.Status = UserStatus.Active;
                //set local account origin
                user.SetAccountOrigin(LOCAL_ACCOUNT_ORIGIN);
                
                //set user verification 
                await user.ReleaseAsync();

                //Revoke token now complete
                _ = RevokedTokens.RevokeAsync(regJwt, CancellationToken.None).ConfigureAwait(false);

                webm.Result = "Successfully created your new account. You may now log in";
                webm.Success = true;
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }
            //Capture creation failed, this may be a replay
            catch (UserExistsException)
            {
            }
            catch(UserCreationFailedException)
            {
            }

            webm.Result = FAILED_AUTH_ERR;
            entity.CloseResponse(webm);
            return VfReturnType.VirtualSkip;
        } 

        protected override async ValueTask<VfReturnType> PutAsync(HttpEntity entity)
        {
            ValErrWebMessage webm = new();
            
            //Get the request
            RegRequestMessage? request = await entity.GetJsonFromFileAsync<RegRequestMessage>();
            if (webm.Assert(request != null, "Request is invalid"))
            {
                entity.CloseResponseJson(HttpStatusCode.BadRequest, webm);
                return VfReturnType.VirtualSkip;
            }

            //Validate the request
            if (!AccountValidations.RegRequestValidator.Validate(request, webm))
            {
                entity.CloseResponseJson(HttpStatusCode.UnprocessableEntity, webm);
                return VfReturnType.VirtualSkip;
            }

            //Create psudo contant time delay
            Task delay = Task.Delay(200);

            //See if a user account already exists
            using (IUser? user = await Users.GetUserFromEmailAsync(request.UserName!, entity.EventCancellation))
            {
                if (user != null)
                {
                    goto Exit;
                }
            }
          
            //Get exact timestamp
            DateTimeOffset timeStamp = DateTimeOffset.UtcNow;

            //generate random nonce for entropy
            string entropy = EntropyNonce;

            //Init client jwt
            string jwtData;
            using (JsonWebToken emailJwt = new())
            {
                emailJwt.WriteHeader(RegSignatureKey.Result.JwtHeader);

                //Init new claim stack, include the same iat time, nonce for entropy, and descriptor storage id
                emailJwt.InitPayloadClaim(3)
                    .AddClaim("iat", timeStamp.ToUnixTimeSeconds())
                    .AddClaim("n", entropy)
                    .AddClaim("email", request.UserName)
                    .CommitClaims();

                //sign the jwt
                emailJwt.SignFromJwk(RegSignatureKey.Result);
                //Compile to encoded string
                jwtData = emailJwt.Compile();
            }

            string regUrl = $"https://{entity.Server.RequestUri.Authority}{Path}?t={jwtData}";

            //Send email to user in background task and do not await it
            _ = SendRegEmailAsync(request.UserName!, regUrl).ConfigureAwait(false);

        Exit:
            //await sort of constant time delay
            await delay;

            //Notify user
            webm.Result = REG_ERR_MESSAGE;
            webm.Success = true;

            entity.CloseResponse(webm);
            return VfReturnType.VirtualSkip;
        }
      

        private async Task SendRegEmailAsync(string emailAddress, string url)
        {
            try
            {
                //Get a new registration template
                EmailTransactionRequest emailTemplate = Emails.GetTemplateRequest("Registration");
                //Add the user's to address
                emailTemplate.AddToAddress(emailAddress);
                emailTemplate.AddVariable("username", emailAddress);
                //Set the security code variable string
                emailTemplate.AddVariable("reg_url", url);
                emailTemplate.AddVariable("date", DateTimeOffset.UtcNow.ToString("f"));
              
                //Send the email
                TransactionResult result = await Emails.SendEmailAsync(emailTemplate);
                
                if (!result.Success)
                {
                    Log.Debug("Registration email failed to send, SMTP status code: {smtp}", result.SmtpStatus);
                }
                else
                {
                    Log.Verbose("Registration email sent to user. Status {smtp}", result.SmtpStatus);
                }
            }
            catch (ValidationFailedException vf)
            {
                //This should only occur if there is a bug in our reigration code that allowed an invalid value pass
                Log.Debug(vf, "Registration email failed to send to user because data validation failed");
            }
            catch (InvalidAuthorizationException iae)
            {
                Log.Warn(iae, "Registration email failed to send due to an authentication error");
            }
            catch (OAuth2AuthenticationException o2e)
            {
                Log.Warn(o2e, "Registration email failed to send due to an authentication error");
            }
            catch (Exception ex)
            {
                Log.Error(ex);
            }
        }

        async Task IIntervalScheduleable.OnIntervalAsync(ILogProvider log, CancellationToken cancellationToken)
        {
            //Cleanup tokens
            await RevokedTokens.CleanTableAsync(RegExpiresSec, cancellationToken);
        }
    }
}