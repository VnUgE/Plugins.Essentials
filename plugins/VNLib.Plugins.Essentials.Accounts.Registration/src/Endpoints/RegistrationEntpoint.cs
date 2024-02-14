/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts.Registration
* File: RegistrationEntpoint.cs 
*
* RegistrationEntpoint.cs is part of VNLib.Plugins.Essentials.Accounts.Registration 
* which is part of the larger VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Accounts.Registration is free software: you can 
* redistribute it and/or modify it under the terms of the GNU Affero General 
* Public License as published by the Free Software Foundation, either version 
* 3 of the License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Accounts.Registration is distributed in the
* hope that it will be useful, but WITHOUT ANY WARRANTY; without even 
* the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR 
* PURPOSE. See the GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

using System;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

using FluentValidation;

using Emails.Transactional.Client;
using Emails.Transactional.Client.Plugins;
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
using VNLib.Plugins.Essentials.Accounts.Registration.TokenRevocation;
using static VNLib.Plugins.Essentials.Accounts.AccountUtil;

namespace VNLib.Plugins.Essentials.Accounts.Registration.Endpoints
{

    [ConfigurationName("registration")]
    internal sealed class RegistrationEntpoint : UnprotectedWebEndpoint
    {
        /// <summary>
        /// Generates a CNG random buffer to use as a nonce
        /// </summary>
        private static string EntropyNonce => RandomHash.GetRandomHex(16);

        const string FAILED_AUTH_ERR = "Your registration does not exist, you should try to regisiter again.";
        const string REG_ERR_MESSAGE = "Please check your email inbox.";

        private static readonly IValidator<RegCompletionRequest> RegCompletionValidator = RegCompletionRequest.GetValidator();

        private readonly IUserManager Users;
        private readonly RevokedTokenStore RevokedTokens;
        private readonly TransactionalEmailConfig Emails;
        private readonly IAsyncLazy<ReadOnlyJsonWebKey> RegSignatureKey;
        private readonly TimeSpan RegExpiresSec;

        /// <summary>
        /// Creates back-end functionality for a "registration" or "sign-up" page that integrates with the <see cref="AccountUtil"/> plugin
        /// </summary>
        /// <param name="Path">The path identifier</param>
        /// <exception cref="ArgumentException"></exception>
        public RegistrationEntpoint(PluginBase plugin, IConfigScope config)
        {
            string? path = config["path"].GetString();

            InitPathAndLog(path, plugin.Log);

            RegExpiresSec = config["reg_expires_sec"].GetTimeSpan(TimeParseType.Seconds);
           
            Users = plugin.GetOrCreateSingleton<UserManager>();           
            Emails = plugin.GetOrCreateSingleton<TEmailConfig>();
            RevokedTokens = new(plugin.GetContextOptionsAsync());

            //Begin the async op to get the signature key from the vault
            RegSignatureKey = plugin.GetSecretAsync("reg_sig_key")
                                .ToLazy(static sr => sr.GetJsonWebKey());
        }

        //Schedule cleanup interval
        [AsyncInterval(Minutes = 5)]
        public async Task OnIntervalAsync(ILogProvider log, CancellationToken cancellationToken)
        {
            //Cleanup tokens
            await RevokedTokens.CleanTableAsync(RegExpiresSec, cancellationToken);
        }


        protected override async ValueTask<VfReturnType> PostAsync(HttpEntity entity)
        {
            ValErrWebMessage webm = new();

            //Get the json request data from client
            using RegCompletionRequest? request = await entity.GetJsonFromFileAsync<RegCompletionRequest>();

            if(webm.Assert(request != null, "No request data present"))
            {
                return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
            }

            if(!RegCompletionValidator.Validate(request, webm))
            {
                return VirtualClose(entity, webm, HttpStatusCode.UnprocessableEntity);
            }

            //Verify jwt has not been revoked      
            bool isRevoked = await RevokedTokens.IsRevokedAsync(request.Token!, entity.EventCancellation);
            if (webm.Assert(!isRevoked, FAILED_AUTH_ERR))
            {
                return VirtualOk(entity, webm);
            }

            string emailAddress;
            try
            {
                //get jwt
                using JsonWebToken jwt = JsonWebToken.Parse(request.Token);

                //verify signature
                bool verified = jwt.VerifyFromJwk(RegSignatureKey.Value);

                if (webm.Assert(verified, FAILED_AUTH_ERR))
                {
                    return VirtualOk(entity, webm);
                }

                //recover iat and email address
                using JsonDocument reg = jwt.GetPayload();
                emailAddress = reg.RootElement.GetPropString("email")!;
                DateTimeOffset iat = DateTimeOffset.FromUnixTimeSeconds(reg.RootElement.GetProperty("iat").GetInt64());

                //Verify IAT against expiration at second resolution
                if (webm.Assert(iat.Add(RegExpiresSec) > entity.RequestedTimeUtc, FAILED_AUTH_ERR))
                {
                    return VirtualOk(entity, webm);
                }
            }
            catch (FormatException fe)
            {
                Log.Debug(fe);
                webm.Result = FAILED_AUTH_ERR;
                return VirtualOk(entity, webm);
            }

            try
            {
                UserCreationRequest creation = new()
                {
                    EmailAddress = emailAddress,
                    InitialStatus = UserStatus.Active,
                    Password = request.GetPassPrivString(),
                };

                //Create the new user with random user-id
                using IUser user = await Users.CreateUserAsync(creation, null, entity.EventCancellation);
                
                //set local account origin
                user.SetAccountOrigin(LOCAL_ACCOUNT_ORIGIN);
                
                //set user verification 
                await user.ReleaseAsync();

                //Revoke token now complete
                _ = RevokedTokens.RevokeAsync(request.Token, CancellationToken.None).ConfigureAwait(false);

                webm.Result = "Successfully created your new account. You may now log in";
                webm.Success = true;

                return VirtualOk(entity, webm);
            }
            //Capture creation failed, this may be a replay
            catch (UserExistsException)
            {
            }
            catch(UserCreationFailedException)
            {
            }

            webm.Result = FAILED_AUTH_ERR;
            return VirtualOk(entity, webm);
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
            using (IUser? user = await Users.GetUserFromUsernameAsync(request.UserName!, entity.EventCancellation))
            {
                if (user != null)
                {
                    goto Exit;
                }
            }
          
            //Get exact timestamp
            DateTimeOffset timeStamp = entity.RequestedTimeUtc;

            //generate random nonce for entropy
            string entropy = EntropyNonce;

            //Init client jwt
            string jwtData;
            using (JsonWebToken emailJwt = new())
            {
                emailJwt.WriteHeader(RegSignatureKey.Value.JwtHeader);

                //Init new claim stack, include the same iat time, nonce for entropy, and descriptor storage id
                emailJwt.InitPayloadClaim(3)
                    .AddClaim("iat", timeStamp.ToUnixTimeSeconds())
                    .AddClaim("n", entropy)
                    .AddClaim("email", request.UserName)
                    .CommitClaims();

                //sign the jwt
                emailJwt.SignFromJwk(RegSignatureKey.Value);
                //Compile to encoded string
                jwtData = emailJwt.Compile();
            }

            string regUrl = $"https://{entity.Server.RequestUri.Authority}{Path}?t={jwtData}";

            //Send email to user in background task and do not await it
            _ = SendRegEmailAsync(request.UserName!, regUrl, timeStamp).ConfigureAwait(false);

        Exit:
            //await sort of constant time delay
            await delay;

            //Notify user
            webm.Result = REG_ERR_MESSAGE;
            webm.Success = true;

            entity.CloseResponse(webm);
            return VfReturnType.VirtualSkip;
        }
      

        private async Task SendRegEmailAsync(string emailAddress, string url, DateTimeOffset current)
        {
            try
            {
                //Get a new registration template
                EmailTransactionRequest emailTemplate = Emails.GetTemplateRequest("Registration");

                //Add the user's to address
                emailTemplate.AddToAddress(emailAddress)
                    .AddVariable("username", emailAddress)
                    //Set the security code variable string
                    .AddVariable("reg_url", url)
                    .AddVariable("date", current.ToString("f"));
              
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


        private sealed class RegCompletionRequest : PrivateStringManager
        {
            public RegCompletionRequest() : base(1)
            { }

            [JsonPropertyName("password")]
            public string? Password
            {
                get => this[0];
                set => this[0] = value;
            }

            [JsonPropertyName("token")]
            public string? Token { get; set; }

            public PrivateString? GetPassPrivString() => PrivateString.ToPrivateString(this[0], false);

            public static IValidator<RegCompletionRequest> GetValidator()
            {
                InlineValidator<RegCompletionRequest> validator = new();

                validator.RuleFor(x => x.Password)
                    .NotEmpty()
                    .SetValidator(AccountValidations.PasswordValidator);

                validator.RuleFor(x => x.Token)
                    .NotEmpty()
                    //Must contain 2 periods for jwt limitation
                    .Must(static s => s!.Count(static s => s == '.') == 2)
                    //Guard length
                    .Length(20, 500)
                    .IllegalCharacters();

                return validator;
            }
        }
    }
}