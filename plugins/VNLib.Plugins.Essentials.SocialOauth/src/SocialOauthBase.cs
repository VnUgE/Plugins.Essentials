/*
* Copyright (c) 2022 Vaughn Nugent
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
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using System.Runtime.InteropServices;

using FluentValidation;

using RestSharp;
using VNLib.Net.Http;
using VNLib.Net.Rest.Client;
using VNLib.Hashing;
using VNLib.Utils;
using VNLib.Utils.Memory;
using VNLib.Utils.Logging;
using VNLib.Utils.Extensions;
using VNLib.Utils.Memory.Caching;
using VNLib.Plugins.Essentials.Users;
using VNLib.Plugins.Essentials.Accounts;
using VNLib.Plugins.Essentials.Endpoints;
using VNLib.Plugins.Essentials.Extensions;
using VNLib.Plugins.Extensions.Validation;
using VNLib.Plugins.Essentials.SocialOauth.Validators;

namespace VNLib.Plugins.Essentials.SocialOauth
{

    /// <summary>
    /// Provides a base class for derriving commong OAuth2 implicit authentication
    /// </summary>
    public abstract class SocialOauthBase : UnprotectedWebEndpoint
    {
        const string AUTH_ERROR_MESSAGE = "You have no pending authentication requests.";

        const string AUTH_GRANT_SESSION_NAME = "auth";

        /// <summary>
        /// The client configuration struct passed during base class construction
        /// </summary>
        protected abstract OauthClientConfig Config { get; }
        
        ///<inheritdoc/>
        protected override ProtectionSettings EndpointProtectionSettings { get; } = new()
        {
            /*
             * Disable cross site checking because the OAuth2 flow requires
             * cross site when redirecting the client back
             */
            DisableCrossSiteDenied = true
        };

        /// <summary>
        /// The resst client connection pool
        /// </summary>
        protected RestClientPool ClientPool { get; }

        private readonly Dictionary<string, LoginClaim> ClaimStore;
        private readonly Dictionary<string, OAuthAccessState> AuthorizationStore;
        private readonly IValidator<LoginClaim> ClaimValidator;
        private readonly IValidator<string> NonceValidator;
        private readonly IValidator<AccountData> AccountDataValidator;

        protected SocialOauthBase()
        {
            ClaimStore = new(StringComparer.OrdinalIgnoreCase);
            AuthorizationStore = new(StringComparer.OrdinalIgnoreCase);
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
            if(entity.LoginCookieMatches() || entity.TokenMatches())
            {
                return false;
            }
            return true;
        }

        /// <summary>
        /// Invoked by the constructor during rest client initlialization
        /// </summary>
        /// <param name="client">The new client to be configured</param>
        protected virtual void StaticClientPoolInitializer(RestClient client)
        {
            client.AddDefaultHeader("accept", HttpHelpers.GetContentTypeString(ContentType.Json));
            client.UseSerializer<RestSharp.Serializers.Json.SystemTextJsonSerializer>();
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
        /// <param name="cancellationToken"></param>
        protected async Task<OAuthAccessState?> ExchangeCodeForTokenAsync(HttpEntity ev, string code, CancellationToken cancellationToken)
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
        /// <param name="cancellationToken"></param>
        protected abstract Task<AccountData?> GetAccountDataAsync(IOAuthAccessState clientAccess, CancellationToken cancellationToken);
        /// <summary>
        /// Gets an object that represents the required information for logging-in a user (namley unique user-id)
        /// </summary>
        /// <param name="clientAccess">The authorization information granted from the OAuth2 authorization server</param>
        /// <param name="cancellation">A token to cancel the operation</param>
        /// <returns></returns>
        protected abstract Task<UserLoginData?> GetLoginDataAsync(IOAuthAccessState clientAccess, CancellationToken cancellation);

        class LoginClaim : ICacheable, INonce
        {
            [JsonPropertyName("public_key")]
            public string? PublicKey { get; set; }
            [JsonPropertyName("browser_id")]
            public string? ClientId { get; set; }

            /// <summary>
            /// The raw OAuth flow state parameter the client must decrypt before 
            /// navigating to remote authentication source
            /// </summary>
            [JsonIgnore]
            public ReadOnlyMemory<byte> RawNonce { get; private set; }
            [JsonIgnore]
            DateTime ICacheable.Expires { get; set; }
            bool IEquatable<ICacheable>.Equals(ICacheable? other) => Equals(other);
            void ICacheable.Evicted()
            {
                //Erase nonce
                MemoryUtil.UnsafeZeroMemory(RawNonce);
            }

            public override bool Equals(object? obj)
            {
                return obj is LoginClaim otherClaim && this.PublicKey!.Equals(otherClaim.PublicKey, StringComparison.Ordinal);
            }
            public override int GetHashCode() => PublicKey!.GetHashCode();

            void INonce.ComputeNonce(Span<byte> buffer)
            {
                RandomHash.GetRandomBytes(buffer);
                //Store copy
                RawNonce = buffer.ToArray();
            }

            bool INonce.VerifyNonce(ReadOnlySpan<byte> nonceBytes)
            {
                return CryptographicOperations.FixedTimeEquals(RawNonce.Span, nonceBytes);
            }
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
                    //The connection was not a browser redirect
                    entity.Redirect(RedirectType.Temporary, $"{Path}?result=bad_sec");
                    return VfReturnType.VirtualSkip;
                }
                //Try to get the claim from the state parameter
                if (ClaimStore.TryGetOrEvictRecord(state, out LoginClaim? claim) < 1)
                {
                    entity.Redirect(RedirectType.Temporary, $"{Path}?result=expired");
                    return VfReturnType.VirtualSkip;
                }
                //Lock on the claim to prevent replay
                lock (claim)
                {
                    bool isValid = claim.VerifyNonce(state);
                    //Evict the record inside the lock, also wipes nonce contents
                    ClaimStore.EvictRecord(state);

                    //Compare binary values of nonce incase of dicionary collision
                    if (!isValid)
                    {
                        entity.Redirect(RedirectType.Temporary, $"{Path}?result=invalid");
                        return VfReturnType.VirtualSkip;
                    }
                }
                //Exchange the OAuth code for a token (application specific)
                OAuthAccessState? token = await ExchangeCodeForTokenAsync(entity, code, entity.EventCancellation);
                //Token may be null
                if(token == null)
                {
                    entity.Redirect(RedirectType.Temporary, $"{Path}?result=invalid");
                    return VfReturnType.VirtualSkip;
                }
                //Store claim info
                token.PublicKey = claim.PublicKey;
                token.ClientId = claim.ClientId;
                //Generate the new nonce
                string nonce = token.ComputeNonce((int)Config.NonceByteSize);
                //Collect expired records
                AuthorizationStore.CollectRecords();
                //Register the access token
                AuthorizationStore.StoreRecord(nonce, token, Config.LoginNonceLifetime);
                //Prepare redirect
                entity.Redirect(RedirectType.Temporary, $"{Path}?result=authorized&nonce={nonce}");
                return VfReturnType.VirtualSkip;
            }
            //Check to see if there was an error code set
            if (entity.QueryArgs.TryGetNonEmptyValue("error", out string? errorCode))
            {
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
            if (AuthorizationStore.TryGetOrEvictRecord(base32Nonce!, out OAuthAccessState? token) < 1)
            {
                webm.Result = AUTH_ERROR_MESSAGE;
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }
            bool valid;
            //Valid token, now verify the nonce within the locked context
            lock (token)
            {
                valid = token.VerifyNonce(base32Nonce);
                //Evict (wipes nonce)
                AuthorizationStore.EvictRecord(base32Nonce!);
            }
            if (webm.Assert(valid, AUTH_ERROR_MESSAGE))
            {
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }
            
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
                //Create new user, create random passwords
                byte[] randomPass = RandomHash.GetRandomBytes(Config.RandomPasswordSize);
                //Generate a new random passowrd incase the user wants to use a local account to log in sometime in the future
                PrivateString passhash = Config.Passwords.Hash(randomPass);
                //overwite the password bytes
                MemoryUtil.InitializeBlock(randomPass.AsSpan());
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
                finally
                {
                    passhash.Dispose();
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
                webm.Token = entity.GenerateAuthorization(token.PublicKey!, token.ClientId!, user);
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
            
            //Cleanup old records
            ClaimStore.CollectRecords();
            //Set nonce
            string base32Nonce = claim.ComputeNonce((int)Config.NonceByteSize);
            //build the redirect url
            webm.Result = BuildUrl(base32Nonce, claim.PublicKey!, entity.IsSecure ? "https" : "http", entity.Server.RequestUri.Authority, entity.Server.Encoding);
            //Store the claim
            ClaimStore.StoreRecord(base32Nonce, claim, Config.LoginNonceLifetime);
            webm.Success = true;
            //Response
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

        private string BuildUrl(string base32Nonce, string pubKey, ReadOnlySpan<char> scheme, ReadOnlySpan<char> redirectAuthority, Encoding enc)
        {
            //Char buffer for base32 and url building
            using UnsafeMemoryHandle<byte> buffer = MemoryUtil.UnsafeAlloc<byte>(8192, true);
            //get bin buffer slice
            Span<byte> binBuffer = buffer.Span[1024..];
            
            ReadOnlySpan<char> url;
            {
                //Get char buffer slice and cast to char
                Span<char> charBuf = MemoryMarshal.Cast<byte, char>(buffer.Span[..1024]);
                //buffer writer for easier syntax
                ForwardOnlyWriter<char> writer = new(charBuf);
                //first build the redirect url to re-encode it
                writer.Append(scheme);
                writer.Append("://");
                //Create redirect url (current page, default action is to authorize the client)
                writer.Append(redirectAuthority);
                writer.Append(Path);
                //url encode the redirect path and save it for later
                string redirectFiltered = Uri.EscapeDataString(writer.ToString());
                //reset the writer again to begin building the path 
                writer.Reset();
                //Append the config redirect path
                writer.Append(Config.AccessCodeUrl.OriginalString);
                //begin query arguments
                writer.Append("&client_id=");
                writer.Append(Config.ClientID);
                //add the redirect url
                writer.Append("&redirect_uri=");
                writer.Append(redirectFiltered);
                //Append the state parameter
                writer.Append("&state=");
                writer.Append(base32Nonce);
                url = writer.AsSpan();
            }
            //Separate buffers
            Span<byte> encryptionBuffer = binBuffer[1024..];
            Span<byte> encodingBuffer = binBuffer[..1024];
            //Encode the url to binary
            int byteCount = enc.GetBytes(url, encodingBuffer);
            //Encrypt the binary
            ERRNO count = AccountUtil.TryEncryptClientData(pubKey, encodingBuffer[..byteCount], in encryptionBuffer);
            //base64 encode the encrypted
            return Convert.ToBase64String(encryptionBuffer[0..(int)count]);
        }
    }
}
