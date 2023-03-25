/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.SocialOauth
* File: SocialOauthBase.cs 
*
* SocialOauthBase.cs is part of VNLib.Plugins.Essentials.SocialOauth which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.SocialOauth is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.SocialOauth is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

using System;
using System.Net;
using System.Text;
using System.Buffers;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using System.Runtime.InteropServices;
using System.Diagnostics.CodeAnalysis;

using FluentValidation;

using RestSharp;

using VNLib.Net.Http;
using VNLib.Net.Rest.Client;
using VNLib.Hashing;
using VNLib.Hashing.IdentityUtility;
using VNLib.Utils;
using VNLib.Utils.Memory;
using VNLib.Utils.Logging;
using VNLib.Utils.Extensions;
using VNLib.Plugins.Essentials.Users;
using VNLib.Plugins.Essentials.Accounts;
using VNLib.Plugins.Essentials.Endpoints;
using VNLib.Plugins.Essentials.Extensions;
using VNLib.Plugins.Essentials.SocialOauth.Validators;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Validation;

using ContentType = VNLib.Net.Http.ContentType;

namespace VNLib.Plugins.Essentials.SocialOauth
{

    /// <summary>
    /// Provides a base class for derriving commong OAuth2 implicit authentication
    /// </summary>
    public abstract class SocialOauthBase : UnprotectedWebEndpoint
    {
        const string AUTH_ERROR_MESSAGE = "You have no pending authentication requests.";

        const string AUTH_GRANT_SESSION_NAME = "auth";
        const string SESSION_SIG_KEY_NAME = "soa.sig";
        const string SESSION_TOKEN_KEY_NAME = "soa.tkn";
        const string CLAIM_COOKIE_NAME = "extern-claim";
        const int SIGNING_KEY_SIZE = 32;

        private static HMAC GetSigningAlg(byte[] key) => new HMACSHA256(key);

        /// <summary>
        /// The client configuration struct passed during base class construction
        /// </summary>
        protected virtual OauthClientConfig Config { get; }
        
        ///<inheritdoc/>
        protected override ProtectionSettings EndpointProtectionSettings { get; } = new();

        /// <summary>
        /// The resst client connection pool
        /// </summary>
        protected RestClientPool ClientPool { get; }
   
        private readonly IValidator<LoginClaim> ClaimValidator;
        private readonly IValidator<string> NonceValidator;
        private readonly IValidator<AccountData> AccountDataValidator;

        protected SocialOauthBase(PluginBase plugin, IConfigScope config)
        {
            ClaimValidator = GetClaimValidator();
            NonceValidator = GetNonceValidator();
            AccountDataValidator = new AccountDataValidator();

            RestClientOptions poolOptions = new()
            {
                MaxTimeout = 5000,
                AutomaticDecompression = DecompressionMethods.All,
                Encoding = Encoding.UTF8,
                //disable redirects, api should not redirect
                FollowRedirects = false,
            };
            
            //Configure rest client to comunications to main discord api
            ClientPool = new(10, poolOptions, StaticClientPoolInitializer);

            //Get the configuration element for the derrived type
            Config = plugin.CreateService<OauthClientConfig>(config);

            //Init endpoint 
            InitPathAndLog(Config.EndpointPath, plugin.Log);
        }

        private static IValidator<LoginClaim> GetClaimValidator()
        {
            InlineValidator<LoginClaim> val = new();
            val.RuleFor(static s => s.ClientId)
                .Length(10, 100)
                .WithMessage("Request is not valid");

            val.RuleFor(static s => s.PublicKey)
                .Length(50, 1024)
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
        /// Invoked by the constructor during rest client initlialization
        /// </summary>
        /// <param name="client">The new client to be configured</param>
        protected virtual void StaticClientPoolInitializer(RestClient client)
        {
            client.AddDefaultHeader("accept", HttpHelpers.GetContentTypeString(ContentType.Json));
        }

        protected virtual void OnBeforeGetToken(HttpEntity entity, string code, RestRequest state) { }

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
            //valid response, time to get the actual authorization from gh for client
            RestRequest request = new(Config.AccessTokenUrl, Method.Post);

            //Add required params url-encoded
            request.AddParameter("client_id", Config.ClientID, ParameterType.GetOrPost);
            request.AddParameter("client_secret", Config.ClientSecret, ParameterType.GetOrPost);
            request.AddParameter("grant_type", "authorization_code", ParameterType.GetOrPost);
            request.AddParameter("code", code, ParameterType.GetOrPost);
            request.AddParameter("redirect_uri", $"{ev.Server.RequestUri.Scheme}://{ev.Server.RequestUri.Authority}{Path}", ParameterType.GetOrPost);

            //Allow reconfiguration
            OnBeforeGetToken(ev, code, request);

            //Get client from pool
            using ClientContract client = ClientPool.Lease();
            //Execute request and attempt to recover the authorization response
            RestResponse<OAuthAccessState> response = await client.Resource.ExecuteAsync<OAuthAccessState>(request, cancellationToken: cancellationToken);
            //Make sure successfull, if so return the access token to store
            return response.IsSuccessful && response.Data != null ? response.Data : null;
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

        sealed class LoginClaim : IClientSecInfo
        {
            [JsonPropertyName("public_key")]
            public string? PublicKey { get; set; }
            
            [JsonPropertyName("browser_id")]
            public string? ClientId { get; set; }

            [JsonPropertyName("exp")]
            public long ExpirationSeconds { get; set; }

            [JsonPropertyName("iat")]
            public long IssuedAtTime { get; set; }           

            [JsonPropertyName("nonce")]
            public string? Nonce { get; set; }
         
            public void ComputeNonce(int nonceSize)
            {
                byte[] buffer = ArrayPool<byte>.Shared.Rent(nonceSize);
                try
                {
                    Span<byte> nonce = buffer.AsSpan(0, nonceSize);

                    //get random data
                    RandomHash.GetRandomBytes(nonce);

                    //Encode nonce
                    Nonce = VnEncoding.ToBase32String(nonce);
                }
                finally
                {
                    MemoryUtil.InitializeBlock(buffer.AsSpan());
                    ArrayPool<byte>.Shared.Return(buffer);
                }
            }
        }

        /*
         * Claims are considered indempodent because they require no previous state
         * and will return a new secret authentication "token" (url + nonce) that 
         * uniquely identifies the claim and authorization upgrade later
         */

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
            webm.Result = new LoginUriBuilder()
                .WithEncoding(entity.Server.Encoding)
                .WithUrl(entity.IsSecure ? "https" : "http", entity.Server.RequestUri.Authority, Path)
                .WithNonce(claim.Nonce!)
                .Build(Config)
                .Encrypt(entity, claim);

            //Sign and set the claim cookie
            SignAndSetCookie(entity, claim);

            webm.Success = true;
            //Response
            entity.CloseResponse(webm);
            return VfReturnType.VirtualSkip;
        }

        /*
         * Get method is invoked when the remote OAuth2 control has been passed back
         * to this server. If successfull should include a code that grants authorization
         * and include a state variable that the client decrypted from an initial claim
         * to prove its identity
         */

        protected override async ValueTask<VfReturnType> GetAsync(HttpEntity entity)
        {
            //Make sure state and code parameters are available
            if (entity.QueryArgs.TryGetNonEmptyValue("state", out string? state) && entity.QueryArgs.TryGetNonEmptyValue("code", out string? code))
            {
                //Disable refer headers when nonce is set
                entity.Server.Headers["Referrer-Policy"] = "no-referrer";
               
                //Check for security navigation headers. This should be a browser redirect,
                if (!entity.Server.IsNavigation() || !entity.Server.IsUserInvoked())
                {
                    ClearClaimData(entity);
                    //The connection was not a browser redirect
                    entity.Redirect(RedirectType.Temporary, $"{Path}?result=bad_sec");
                    return VfReturnType.VirtualSkip;
                }

                //Try to get the claim from the state parameter
                if (!VerifyAndGetClaim(entity, out LoginClaim? claim))
                {
                    ClearClaimData(entity);
                    entity.Redirect(RedirectType.Temporary, $"{Path}?result=expired");
                    return VfReturnType.VirtualSkip;
                }

                //Confirm the nonce matches the claim
                if (string.CompareOrdinal(claim.Nonce, state) != 0)
                {
                    ClearClaimData(entity);
                    entity.Redirect(RedirectType.Temporary, $"{Path}?result=invalid");
                    return VfReturnType.VirtualSkip;
                }

                //Exchange the OAuth code for a token (application specific)
                OAuthAccessState? token = await ExchangeCodeForTokenAsync(entity, code, entity.EventCancellation);

                //Token may be null
                if (token == null)
                {
                    ClearClaimData(entity);
                    entity.Redirect(RedirectType.Temporary, $"{Path}?result=invalid");
                    return VfReturnType.VirtualSkip;
                }

                //Create the new nonce
                claim.ComputeNonce((int)Config.NonceByteSize);

                //Store access state in the user's session
                entity.Session.SetObject(SESSION_TOKEN_KEY_NAME, token);

                //Sign and set cookie
                SignAndSetCookie(entity, claim);
                  
                //Prepare redirect
                entity.Redirect(RedirectType.Temporary, $"{Path}?result=authorized&nonce={claim.Nonce}");
                return VfReturnType.VirtualSkip;
            }
            
            //Check to see if there was an error code set
            if (entity.QueryArgs.TryGetNonEmptyValue("error", out string? errorCode))
            {
                ClearClaimData(entity);
                Log.Debug("{Type} error {err}:{des}", Config.AccountOrigin, errorCode, entity.QueryArgs["error_description"]);
                entity.Redirect(RedirectType.Temporary, $"{Path}?result=error");
                return VfReturnType.VirtualSkip;
            }
            
            return VfReturnType.ProcessAsFile;
        }

        /*
         * Post messages finalize a login from a nonce
         */

        protected override async ValueTask<VfReturnType> PostAsync(HttpEntity entity)
        {
            ValErrWebMessage webm = new();
            
            //Get the finalization message
            using JsonDocument? request = await entity.GetJsonFromFileAsync();
            
            if (webm.Assert(request != null, "Request message is required"))
            {
                entity.CloseResponseJson(HttpStatusCode.BadRequest, webm);
                return VfReturnType.VirtualSkip;
            }
            
            //Recover the nonce
            string? base32Nonce = request.RootElement.GetPropString("nonce");

            if(webm.Assert(base32Nonce != null, message: "Nonce parameter is required"))
            {
                entity.CloseResponseJson(HttpStatusCode.UnprocessableEntity, webm);
                return VfReturnType.VirtualSkip;
            }
            
            //Validate nonce
            if (!NonceValidator.Validate(base32Nonce, webm))
            {
                entity.CloseResponseJson(HttpStatusCode.UnprocessableEntity, webm);
                return VfReturnType.VirtualSkip;
            }

            //Recover the access token
            bool cookieValid = VerifyAndGetClaim(entity, out LoginClaim? claim);

            if (webm.Assert(cookieValid, AUTH_ERROR_MESSAGE))
            {
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }

            //We can clear the client's access claim
            ClearClaimData(entity);

            //Confirm nonce matches the client's nonce string
            bool nonceValid = string.CompareOrdinal(claim.Nonce, base32Nonce) == 0;

            if (webm.Assert(nonceValid, AUTH_ERROR_MESSAGE))
            {
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }           

            //Safe to recover the access token
            IOAuthAccessState token = entity.Session.GetObject<OAuthAccessState>(SESSION_TOKEN_KEY_NAME);
            
            //get the user's login information (ie userid)
            UserLoginData? userLogin = await GetLoginDataAsync(token, entity.EventCancellation);
            
            if(webm.Assert(userLogin?.UserId != null, AUTH_ERROR_MESSAGE))
            {
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }
            
            //Fetch the user from the database
            IUser? user = await Config.Users.GetUserFromIDAsync(userLogin.UserId, entity.EventCancellation);
            
            if(user == null)
            {
                //Get the clients personal info to being login process
                AccountData? userAccount = await GetAccountDataAsync(token, entity.EventCancellation);

                if (webm.Assert(userAccount != null, AUTH_ERROR_MESSAGE))
                {
                    entity.CloseResponse(webm);
                    return VfReturnType.VirtualSkip;
                }

                //Validate the account data
                if (webm.Assert(AccountDataValidator.Validate(userAccount).IsValid, AUTH_ERROR_MESSAGE))
                {
                    entity.CloseResponse(webm);
                    return VfReturnType.VirtualSkip;
                }

                //make sure registration is enabled
                if (webm.Assert(Config.AllowRegistration, AUTH_ERROR_MESSAGE))
                {
                    entity.CloseResponse(webm);
                    return VfReturnType.VirtualSkip;
                }
              
                //Generate a new random passowrd incase the user wants to use a local account to log in sometime in the future
                using PrivateString passhash = Config.Passwords.GetRandomPassword(Config.RandomPasswordSize);
                try
                {
                    //Create the user with the specified email address, minimum privilage level, and an empty password
                    user = await Config.Users.CreateUserAsync(userLogin.UserId!, userAccount.EmailAddress, AccountUtil.MINIMUM_LEVEL, passhash, entity.EventCancellation);
                    //Set active status
                    user.Status = UserStatus.Active;
                    //Store the new profile
                    user.SetProfile(userAccount);
                    //Set the account creation origin
                    user.SetAccountOrigin(Config.AccountOrigin);
                }
                catch(UserCreationFailedException)
                {
                    Log.Warn("Failed to create new user from new OAuth2 login, because a creation exception occured");
                    webm.Result = "Please try again later";
                    entity.CloseResponse(webm);
                    return VfReturnType.VirtualSkip;
                }
            }
            else
            {
                //Check for local only
                if (webm.Assert(!user.LocalOnly, AUTH_ERROR_MESSAGE))
                {
                    entity.CloseResponse(webm);
                    return VfReturnType.VirtualSkip;
                }

                //Make sure local accounts are allowed
                if (webm.Assert(!user.IsLocalAccount() || Config.AllowForLocalAccounts, AUTH_ERROR_MESSAGE))
                {
                    entity.CloseResponse(webm);
                    return VfReturnType.VirtualSkip;
                }

                //Reactivate inactive accounts
                if(user.Status == UserStatus.Inactive)
                {
                    user.Status = UserStatus.Active;
                }                
                
                //Make sure the account is active                
                if(webm.Assert(user.Status == UserStatus.Active, AUTH_ERROR_MESSAGE))
                {
                    entity.CloseResponse(webm);
                    return VfReturnType.VirtualSkip;
                }
            }
            //Finalze login
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
                Log.Debug("Successful login for user {uid}... from {ip}", user.UserID[..8], entity.TrustedRemoteIp);
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
            catch(UserUpdateException uue)
            {
                webm.Token = null;
                webm.Result = AUTH_ERROR_MESSAGE;
                webm.Success = false;
                
                //destroy any login data on failure
                entity.InvalidateLogin();
                
                Log.Error(uue);
            }
            finally
            {
                user.Dispose();
            }
            entity.CloseResponse(webm);
            return VfReturnType.VirtualSkip;
        }
     
       

        /*
         * Construct the client's redirect url based on their login claim, which contains
         * a public key which can be used to encrypt the url so that only the client 
         * private-key holder can decrypt the url and redirect themselves to the 
         * target OAuth website. 
         * 
         * The result is an encrypted nonce that should guard against replay attacks and MITM
         */

        sealed class LoginUriBuilder 
        {
            private readonly IMemoryHandle<byte> _buffer;

            private Span<byte> _binBuffer => _buffer.Span[1024..];
            private Span<char> _charBuffer => MemoryMarshal.Cast<byte, char>(_buffer.Span[..1024]);

            private string? redirectUrl;
            private string? nonce;
            private Encoding _encoding;

            private int _urlCharPointer;

            public LoginUriBuilder()
            {
                //Alloc buffer
                _buffer = MemoryUtil.SafeAllocNearestPage<byte>(8000, true);

                //Set default encoding
                _encoding = Encoding.UTF8;
            }

            public LoginUriBuilder WithUrl(ReadOnlySpan<char> scheme, ReadOnlySpan<char> authority, ReadOnlySpan<char> path)
            {
                //buffer writer for easier syntax
                ForwardOnlyWriter<char> writer = new(_charBuffer);
                //first build the redirect url to re-encode it
                writer.Append(scheme);
                writer.Append("://");
                //Create redirect url (current page, default action is to authorize the client)
                writer.Append(authority);
                writer.Append(path);
                //url encode the redirect path and save it for later
                redirectUrl = Uri.EscapeDataString(writer.ToString());

                return this;
            }

            public LoginUriBuilder WithEncoding(Encoding encoding) 
            {
                _encoding = encoding;
                return this;
            }

            public LoginUriBuilder WithNonce(string base32Nonce)
            {
                nonce = base32Nonce;
                return this;
            }

            public LoginUriBuilder Build(OauthClientConfig config)
            {
                //buffer writer for easier syntax
                ForwardOnlyWriter<char> writer = new(_charBuffer);

                //Append the config redirect path
                writer.Append(config.AccessCodeUrl.OriginalString);
                //begin query arguments
                writer.Append("&client_id=");
                writer.Append(config.ClientID);
                //add the redirect url
                writer.Append("&redirect_uri=");
                writer.Append(redirectUrl);
                //Append the state parameter
                writer.Append("&state=");
                writer.Append(nonce);

                //Update url pointer
                _urlCharPointer = writer.Written;

                return this;
            }

            public string Encrypt(HttpEntity client, IClientSecInfo secInfo)
            {
                try
                {
                    ReadOnlySpan<char> url = _charBuffer[.._urlCharPointer];

                    //Separate buffers
                    Span<byte> encryptionBuffer = _binBuffer[1024..];
                    Span<byte> encodingBuffer = _binBuffer[..1024];

                    //Encode the url to binary
                    int byteCount = _encoding.GetBytes(url, encodingBuffer);

                    //Encrypt the binary data
                    ERRNO count = client.TryEncryptClientData(secInfo, encodingBuffer[..byteCount], encryptionBuffer);

                    //base64 encode the encrypted
                    return Convert.ToBase64String(encryptionBuffer[0..(int)count]);
                }
                finally
                {
                    _urlCharPointer = 0;
                    //Dispose buffer
                    _buffer.Dispose();
                }
            }

        }

        private static bool VerifyAndGetClaim(HttpEntity entity, [NotNullWhen(true)] out LoginClaim? claim)
        {
            claim = null;

            //Try to get the cookie
            if(!entity.Server.GetCookie(CLAIM_COOKIE_NAME, out string? cookieValue))
            {
                return false;
            }

            //Recover the signing key from the user's session
            string sigKey = entity.Session[SESSION_SIG_KEY_NAME];
            byte[]? key = VnEncoding.FromBase32String(sigKey);

            if (key == null)
            {
                return false;
            }          

            try
            {
                //Try to parse the jwt
                using JsonWebToken jwt = JsonWebToken.Parse(cookieValue);

                //Verify the jwt
                using(HMAC alg = GetSigningAlg(key))
                {
                    if (!jwt.Verify(alg))
                    {
                        return false;
                    }
                }

                //Recover the clam from the jwt
                claim = jwt.GetPayload<LoginClaim>();

                //Verify the expiration time
                return claim.ExpirationSeconds > entity.RequestedTimeUtc.ToUnixTimeSeconds();
            }
            catch (FormatException)
            {
                return false;
            }
            finally
            {
                MemoryUtil.InitializeBlock(key.AsSpan());
            }
        }

        private static void ClearClaimData(HttpEntity entity) 
        {
            if (entity.Server.RequestCookies.ContainsKey(CLAIM_COOKIE_NAME))
            {
                entity.Server.ExpireCookie(CLAIM_COOKIE_NAME);
            }

            entity.Session[SESSION_SIG_KEY_NAME] = null!;
        }

        private void SignAndSetCookie(HttpEntity entity, LoginClaim claim) 
        {
            //Setup Jwt
            using JsonWebToken jwt = new();

            //Write claim body
            jwt.WritePayload(claim);

            //Generate signing key
            byte[] sigKey = RandomHash.GetRandomBytes(SIGNING_KEY_SIZE);

            //Sign the jwt
            using(HMAC alg = GetSigningAlg(sigKey))
            {
                jwt.Sign(alg);
            }

            //Build and set cookie
            HttpCookie cookie = new(CLAIM_COOKIE_NAME, jwt.Compile())
            {
                Secure = true,
                HttpOnly = true,
                ValidFor = Config.InitClaimValidFor,
                SameSite = CookieSameSite.SameSite
            };

            entity.Server.SetCookie(in cookie);

            //Encode and store the signing key in the clien't session
            entity.Session[SESSION_SIG_KEY_NAME] = VnEncoding.ToBase32String(sigKey);

            MemoryUtil.InitializeBlock(sigKey.AsSpan());
        }
    }
}
