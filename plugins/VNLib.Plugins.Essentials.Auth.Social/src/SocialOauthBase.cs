/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Auth.Social
* File: SocialOauthBase.cs 
*
* SocialOauthBase.cs is part of VNLib.Plugins.Essentials.Auth.Social which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Auth.Social is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Auth.Social is distributed in the hope that it will be useful,
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
using System.Security.Cryptography;
using System.Text.Json.Serialization;

using FluentValidation;

using RestSharp;

using VNLib.Net.Http;
using VNLib.Utils;
using VNLib.Utils.Logging;
using VNLib.Utils.Extensions;
using VNLib.Net.Rest.Client.Construction;
using VNLib.Plugins.Essentials.Users;
using VNLib.Plugins.Essentials.Accounts;
using VNLib.Plugins.Essentials.Endpoints;
using VNLib.Plugins.Essentials.Extensions;
using VNLib.Plugins.Essentials.Auth.Social.Validators;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Validation;
using VNLib.Plugins.Extensions.Loading.Users;

using ContentType = VNLib.Net.Http.ContentType;

namespace VNLib.Plugins.Essentials.Auth.Social
{

    /// <summary>
    /// Provides a base class for derriving commong OAuth2 implicit authentication
    /// </summary>
    public abstract class SocialOauthBase : UnprotectedWebEndpoint
    {
        const string AUTH_ERROR_MESSAGE = "You have no pending authentication requests.";

        const string AUTH_GRANT_SESSION_NAME = "auth";
        const string SESSION_TOKEN_KEY_NAME = "soa.tkn";
        const string CLAIM_COOKIE_NAME = "extern-claim";

        private static readonly IValidator<LoginClaim> ClaimValidator = GetClaimValidator();
        private static readonly IValidator<string> NonceValidator = GetNonceValidator();
        private static readonly AccountDataValidator AccountDataValidator = new ();


        /// <summary>
        /// The client configuration struct passed during base class construction
        /// </summary>
        protected virtual OauthClientConfig Config { get; }

        ///<inheritdoc/>
        protected override ProtectionSettings EndpointProtectionSettings { get; } 

        /// <summary>
        /// The site adapter used to make requests to the OAuth2 provider
        /// </summary>
        protected OAuthSiteAdapter SiteAdapter { get; }

        /// <summary>
        /// The user manager used to create and manage user accounts
        /// </summary>
        protected IUserManager Users { get; }


        private readonly ClientClaimManager _claims;

        protected SocialOauthBase(PluginBase plugin, IConfigScope config)
        {
            //Get the configuration element for the derrived type
            Config = plugin.CreateService<OauthClientConfig>(config);

            //Init endpoint 
            InitPathAndLog(Config.EndpointPath, plugin.Log);

            Users = plugin.GetOrCreateSingleton<UserManager>();


            //Setup cookie controller and claim manager
            SingleCookieController cookies = new(CLAIM_COOKIE_NAME, Config.InitClaimValidFor)
            {
                Secure = true,
                HttpOnly = true,
                SameSite = CookieSameSite.None,
                Path = Path
            };

            _claims = new(cookies, Config.EndpointPath);

            //Define the site adapter
            SiteAdapter = new();

            //Define the the get-token request endpoint
            SiteAdapter.DefineSingleEndpoint()
                .WithEndpoint<GetTokenRequest>()
                .WithMethod(Method.Post)
                .WithUrl(Config.AccessTokenUrl)
                .WithHeader("Accept", HttpHelpers.GetContentTypeString(ContentType.Json))
                .WithParameter("client_id", c => Config.ClientID.Value)
                .WithParameter("client_secret", c => Config.ClientSecret.Value)
                .WithParameter("grant_type", "authorization_code")
                .WithParameter("code", r => r.Code)
                .WithParameter("redirect_uri", r => r.RedirectUrl);
        }

        private static IValidator<LoginClaim> GetClaimValidator()
        {
            InlineValidator<LoginClaim> val = new();
            val.RuleFor(static s => s.ClientId)
                .Length(10, 100)
                .WithMessage("Request is not valid")
                .AlphaNumericOnly()
                .WithMessage("Request is not valid");

            val.RuleFor(static s => s.PublicKey)
                .Length(50, 1024)
                .WithMessage("Request is not valid");

            val.RuleFor(static s => s.LocalLanguage)
                .Length(2, 10)
                .WithMessage("Request is not valid");

            return val;
        }

        private static IValidator<string> GetNonceValidator()
        {
            InlineValidator<string> val = new();
            val.RuleFor(static s => s)
                .Length(10, 200)
                //Nonces are base32, so only alpha num
                .AlphaNumeric();
            return val;
        }

        ///<inheritdoc/>
        protected override ERRNO PreProccess(HttpEntity entity)
        {
            if (!base.PreProccess(entity))
            {
                return false;
            }

            /*
             * Cross site checking is disabled because we need to allow cross site
             * for OAuth2 redirect flows
             */
            if (entity.Server.Method != HttpMethod.GET && entity.Server.IsCrossSite())
            {
                return false;
            }

            //Make sure the user is not logged in
            return !entity.IsClientAuthorized(AuthorzationCheckLevel.Any);
        }

        /// <summary>
        /// When derrived in a child class, exchanges an OAuth2 code grant type
        /// for an OAuth2 access token to make api requests
        /// </summary>
        /// <param name="ev"></param>
        /// <param name="code">The raw code from the remote OAuth2 granting server</param>
        /// <param name="cancellationToken">A token to cancel the operation</param>
        /// <returns>
        /// A task the resolves the <see cref="OAuthAccessState"/> that includes all relavent
        /// authorization data. Result may be null if authorzation is invalid or not granted
        /// </returns>
        protected virtual async Task<OAuthAccessState?> ExchangeCodeForTokenAsync(HttpEntity ev, string code, CancellationToken cancellationToken)
        {
            //Create new request object
            GetTokenRequest req = new(code, $"{ev.Server.RequestUri.Scheme}://{ev.Server.RequestUri.Authority}{Path}");

            //Execute request and attempt to recover the authorization response
            Oauth2TokenResult? response = await SiteAdapter.ExecuteAsync(req, cancellationToken).AsJson<Oauth2TokenResult>();

            if (response?.Error != null)
            {
                Log.Debug("Error result from {conf} code {code} description: {err}", Config.AccountOrigin, response.Error, response.ErrorDescription);
                return null;
            }

            return response;
        }

        /// <summary>
        /// Gets an object that represents the user's account data from the OAuth provider when 
        /// creating a new user for the current platform
        /// </summary>
        /// <param name="clientAccess">The access state from the code/token exchange</param>
        /// <param name="cancellationToken">A token to cancel the operation</param>
        /// <returns>The user's account data, null if not account exsits on the remote site, and process cannot continue</returns>
        protected abstract Task<AccountData?> GetAccountDataAsync(IOAuthAccessState clientAccess, CancellationToken cancellationToken);

        /// <summary>
        /// Gets an object that represents the required information for logging-in a user (namley unique user-id)
        /// </summary>
        /// <param name="clientAccess">The authorization information granted from the OAuth2 authorization server</param>
        /// <param name="cancellation">A token to cancel the operation</param>
        /// <returns></returns>
        protected abstract Task<UserLoginData?> GetLoginDataAsync(IOAuthAccessState clientAccess, CancellationToken cancellation);



        /*
         * Claims are considered indempodent because they require no previous state
         * and will return a new secret authentication "token" (url + nonce) that 
         * uniquely identifies the claim and authorization upgrade later
         */

        ///<inheritdoc/>
        protected override async ValueTask<VfReturnType> PutAsync(HttpEntity entity)
        {
            ValErrWebMessage webm = new();

            //Get the login message
            LoginClaim? claim = await entity.GetJsonFromFileAsync<LoginClaim>();

            if (webm.Assert(claim != null, "Emtpy message body"))
            {
                entity.CloseResponseJson(HttpStatusCode.BadRequest, webm);
                return VfReturnType.VirtualSkip;
            }

            //Validate the message
            if (!ClaimValidator.Validate(claim, webm))
            {
                entity.CloseResponseJson(HttpStatusCode.UnprocessableEntity, webm);
                return VfReturnType.VirtualSkip;
            }

            //Configure the login claim
            claim.IssuedAtTime = entity.RequestedTimeUtc.ToUnixTimeSeconds();

            //Set expiration time in seconds
            claim.ExpirationSeconds = entity.RequestedTimeUtc.Add(Config.InitClaimValidFor).ToUnixTimeMilliseconds();

            //Set nonce
            claim.ComputeNonce((int)Config.NonceByteSize);

            //Build the redirect uri
            webm.Result = new LoginUriBuilder(Config)
                .WithEncoding(entity.Server.Encoding)
                .WithUrl(entity.Server.RequestUri.Scheme, entity.Server.RequestUri.Authority, Path)
                .WithNonce(claim.Nonce!)
                .Encrypt(entity, claim);

            //Sign and set the claim cookie
            _claims.SignAndSetCookie(entity, claim);

            webm.Success = true;
            //Response
            return VirtualOk(entity, webm);
        }

        /*
         * Get method is invoked when the remote OAuth2 control has been passed back
         * to this server. If successful should include a code that grants authorization
         * and include a state variable that the client decrypted from an initial claim
         * to prove its identity
         */

        ///<inheritdoc/>
        protected override async ValueTask<VfReturnType> GetAsync(HttpEntity entity)
        {
            //Make sure state and code parameters are available
            if (entity.QueryArgs.TryGetNonEmptyValue("state", out string? state) 
                && entity.QueryArgs.TryGetNonEmptyValue("code", out string? code))
            {
                //Disable refer headers when nonce is set
                entity.Server.Headers["Referrer-Policy"] = "no-referrer";

                //Check for security navigation headers. This should be a browser redirect,
                if (!entity.Server.IsNavigation() || !entity.Server.IsUserInvoked())
                {
                    _claims.ClearClaimData(entity);
                    //The connection was not a browser redirect
                    entity.Redirect(RedirectType.Temporary, $"{Path}?result=bad_sec");
                    return VfReturnType.VirtualSkip;
                }

                //Try to get the claim from the state parameter
                if (!_claims.VerifyAndGetClaim(entity, out LoginClaim? claim))
                {
                    _claims.ClearClaimData(entity);
                    entity.Redirect(RedirectType.Temporary, $"{Path}?result=expired");
                    return VfReturnType.VirtualSkip;
                }

                //Confirm the nonce matches the claim
                if (string.CompareOrdinal(claim.Nonce, state) != 0)
                {
                    _claims.ClearClaimData(entity);
                    entity.Redirect(RedirectType.Temporary, $"{Path}?result=invalid");
                    return VfReturnType.VirtualSkip;
                }

                //Exchange the OAuth code for a token (application specific)
                OAuthAccessState? token = await ExchangeCodeForTokenAsync(entity, code, entity.EventCancellation);

                //Token may be null
                if (token == null)
                {
                    _claims.ClearClaimData(entity);
                    entity.Redirect(RedirectType.Temporary, $"{Path}?result=invalid");
                    return VfReturnType.VirtualSkip;
                }

                //Create the new nonce
                claim.ComputeNonce((int)Config.NonceByteSize);

                //Store access state in the user's session
                entity.Session.SetObject(SESSION_TOKEN_KEY_NAME, token);

                //Sign and set cookie
                _claims.SignAndSetCookie(entity, claim);

                //Prepare redirect
                entity.Redirect(RedirectType.Temporary, $"{Path}?result=authorized&nonce={claim.Nonce}");
                return VfReturnType.VirtualSkip;
            }

            //Check to see if there was an error code set
            if (entity.QueryArgs.TryGetNonEmptyValue("error", out string? errorCode))
            {
                _claims.ClearClaimData(entity);
                Log.Debug("{Type} error {err}:{des}", Config.AccountOrigin, errorCode, entity.QueryArgs["error_description"]);
                entity.Redirect(RedirectType.Temporary, $"{Path}?result=error");
                return VfReturnType.VirtualSkip;
            }

            return VfReturnType.ProcessAsFile;
        }

        /*
         * Post messages finalize a login from a nonce
         */

        ///<inheritdoc/>
        protected override async ValueTask<VfReturnType> PostAsync(HttpEntity entity)
        {
            ValErrWebMessage webm = new();

            //Get the finalization message
            using JsonDocument? request = await entity.GetJsonFromFileAsync();

            if (webm.Assert(request != null, "Request message is required"))
            {
                return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
            }

            //Recover the nonce
            string? base32Nonce = request.RootElement.GetPropString("nonce");

            if(webm.Assert(base32Nonce != null, "Nonce parameter is required"))
            {
                return VirtualClose(entity, webm, HttpStatusCode.UnprocessableEntity);
            }

            //Validate nonce
            if (!NonceValidator.Validate(base32Nonce, webm))
            {
                return VirtualClose(entity, webm, HttpStatusCode.UnprocessableEntity);
            }

            //Recover the access token
            if (webm.Assert(_claims.VerifyAndGetClaim(entity, out LoginClaim? claim), AUTH_ERROR_MESSAGE))
            {
                return VirtualOk(entity, webm);
            }

            //We can clear the client's access claim
            _claims.ClearClaimData(entity);

            //Confirm nonce matches the client's nonce string
            bool nonceValid = string.CompareOrdinal(claim.Nonce, base32Nonce) == 0;

            if (webm.Assert(nonceValid, AUTH_ERROR_MESSAGE))
            {
                return VirtualOk(entity, webm);
            }

            //Safe to recover the access token
            IOAuthAccessState token = entity.Session.GetObject<OAuthAccessState>(SESSION_TOKEN_KEY_NAME);

            //get the user's login information (ie userid)
            UserLoginData? userLogin = await GetLoginDataAsync(token, entity.EventCancellation);

            if(webm.Assert(userLogin?.UserId != null, AUTH_ERROR_MESSAGE))
            {
                return VirtualOk(entity, webm);
            }

            //Convert the platform user-id to a database-safe user-id
            string computedId = Users.ComputeSafeUserId(userLogin.UserId!);

            //Fetch the user from the database
            IUser? user = await Users.GetUserFromIDAsync(computedId, entity.EventCancellation);

            /*
             * If a user is not found, we can optionally create a new user account
             * if the configuration allows it.
             */
            if (user == null)
            {
                //make sure registration is enabled
                if (webm.Assert(Config.AllowRegistration, AUTH_ERROR_MESSAGE))
                {
                    return VirtualOk(entity, webm);
                }

                //Get the clients personal info to being login process
                AccountData? userAccount = await GetAccountDataAsync(token, entity.EventCancellation);

                if (webm.Assert(userAccount != null, AUTH_ERROR_MESSAGE))
                {
                    return VirtualOk(entity, webm);
                }

                //Validate the account data
                if (webm.Assert(AccountDataValidator.Validate(userAccount).IsValid, AUTH_ERROR_MESSAGE))
                {
                    return VirtualOk(entity, webm);
                }

                //See if user by email address exists
                user = await Users.GetUserFromUsernameAsync(userAccount.EmailAddress!, entity.EventCancellation);

                if (user == null)
                {
                    //Create the new user account
                    UserCreationRequest creation = new()
                    {
                        Username = userAccount.EmailAddress!,
                        InitialStatus = UserStatus.Active,
                        Privileges = AccountUtil.MINIMUM_LEVEL
                    };

                    try
                    {
                        //Create the user with the specified email address, minimum privilage level, and an empty password
                        user = await Users.CreateUserAsync(
                            creation,
                            userId: computedId,
                            hashProvider: Users.GetHashProvider(),
                            entity.EventCancellation
                        );

                        //Store the new profile and origin
                        user.SetProfile(userAccount);
                        user.SetAccountOrigin(Config.AccountOrigin);
                    }
                    catch (UserCreationFailedException)
                    {
                        Log.Warn("Failed to create new user from new OAuth2 login, because a creation exception occured");
                        webm.Result = "Please try again later";
                        return VirtualOk(entity, webm);
                    }

                    //Skip check since we just created the user
                    goto Authorize;
                }

                /*
                * User account already exists via email address but not 
                * user-id
                */
            }

            //Make sure local accounts are allowed
            if (webm.Assert(!user.IsLocalAccount() || Config.AllowForLocalAccounts, AUTH_ERROR_MESSAGE))
            {
                return VirtualOk(entity, webm);
            }

            //Reactivate inactive accounts
            if (user.Status == UserStatus.Inactive)
            {
                user.Status = UserStatus.Active;
            }

            //Make sure the account is active                
            if (webm.Assert(user.Status == UserStatus.Active, AUTH_ERROR_MESSAGE))
            {
                return VirtualOk(entity, webm);
            }

        Authorize:

            try
            {
                //Generate authoization
                entity.GenerateAuthorization(claim, user, webm);

                //Store the user current oauth information in the current session for others to digest
                entity.Session.SetObject($"{Config.AccountOrigin}.{AUTH_GRANT_SESSION_NAME}", token);

                //Send the username back to the client
                webm.Result = new AccountData()
                {
                    EmailAddress = user.EmailAddress,
                };

                //Set the success flag
                webm.Success = true;

                //Write to log
                Log.Debug("Successful social login for user {uid}... from {ip}", user.UserID[..8], entity.TrustedRemoteIp);

                //release the user 
                await user.ReleaseAsync();
            }
            catch (CryptographicException ce)
            {
                Log.Debug("Failed to generate authorization for {user}, error {err}", user.UserID, ce.Message);
                webm.Result = AUTH_ERROR_MESSAGE;
            }
            catch (OutOfMemoryException)
            {
                Log.Debug("Out of buffer space for token data encryption, for user {usr}, from ip {ip}", user.UserID, entity.TrustedRemoteIp);
                webm.Result = AUTH_ERROR_MESSAGE;
            }
            catch (UserUpdateException uue)
            {
                webm.Token = null;
                webm.Result = AUTH_ERROR_MESSAGE;
                webm.Success = false;

                //destroy any login data on failure
                entity.InvalidateLogin();

                Log.Error("Failed to update the user's account cause:\n{err}",uue);
            }
            finally
            {
                user.Dispose();
            }
            return VirtualOk(entity, webm);
        }

        private sealed class Oauth2TokenResult: OAuthAccessState
        {
            [JsonPropertyName("error")]
            public string? Error { get; set; }

            [JsonPropertyName("error_description")]
            public string? ErrorDescription { get; set; }
        }

    }
}
