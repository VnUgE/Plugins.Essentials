/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: AccountSecProvider.cs 
*
* AccountSecProvider.cs is part of VNLib.Plugins.Essentials.Accounts which is part of the larger 
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


/*
 * Implements the IAccountSecurityProvider interface to provide the shared
 * service to the host application for securing user/account based connections
 * via authorization.
 * 
 * This system is technically configurable and optionally loadable
 */

using System;
using System.Text.Json;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Serialization;

using FluentValidation;

using VNLib.Hashing;
using VNLib.Hashing.IdentityUtility;
using VNLib.Net.Http;
using VNLib.Utils;
using VNLib.Utils.Memory;
using VNLib.Utils.Extensions;
using VNLib.Plugins.Essentials.Users;
using VNLib.Plugins.Essentials.Sessions;
using VNLib.Plugins.Essentials.Middleware;
using VNLib.Plugins.Essentials.Extensions;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Validation;

namespace VNLib.Plugins.Essentials.Accounts.SecurityProvider
{

    [ConfigurationName("account_security", Required = false)]
    internal class AccountSecProvider : IAccountSecurityProvider, IHttpMiddleware
    {
        private const int PUB_KEY_JWT_NONCE_SIZE = 16;

        //Session entry keys
        private const string PUBLIC_KEY_SIG_KEY_ENTRY = "acnt.pbsk";

        private const HashAlg ClientTokenHmacType = HashAlg.SHA256;

        /// <summary>
        /// The client data encryption padding.
        /// </summary>
        public static readonly RSAEncryptionPadding ClientEncryptonPadding = RSAEncryptionPadding.OaepSHA256;

        private readonly AccountSecConfig _config;
        private readonly CookieHandler _cookieHandler;

        public AccountSecProvider(PluginBase plugin)
        {
            //Setup default config
            _config = new();
            _cookieHandler = new(_config);
        }

        public AccountSecProvider(PluginBase pbase, IConfigScope config)
        {
            //Parse config if defined
            _config = config.DeserialzeAndValidate<AccountSecConfig>();
            _cookieHandler = new(_config);
        }

        /*
         * Middleware handler for reconciling client cookies for all connections
         */

        ///<inheritdoc/>
        public ValueTask<FileProcessArgs> ProcessAsync(HttpEntity entity)
        {
            //Session must be set and web based for checks
            if (entity.Session.IsSet && entity.Session.SessionType == SessionType.Web)
            {
                //See if the session might be elevated
                if (!string.IsNullOrWhiteSpace(entity.Session.LoginHash))
                {
                    //If the session stored a user-agent, make sure it matches the connection
                    if (entity.Session.UserAgent != null && !entity.Session.UserAgent.Equals(entity.Server.UserAgent, StringComparison.Ordinal))
                    {
                        return ValueTask.FromResult(FileProcessArgs.Deny);
                    }
                }

                //If the session is new, or not supposed to be logged in, clear the login cookies if they were set
                if (entity.Session.IsNew || string.IsNullOrEmpty(entity.Session.LoginHash) || string.IsNullOrEmpty(entity.Session.Token))
                {
                    ExpireCookies(entity);
                }
            }

            //Always continue otherwise
            return ValueTask.FromResult(FileProcessArgs.Continue);
        }


        #region Interface Impl

        ///<inheritdoc/>
        IClientAuthorization IAccountSecurityProvider.AuthorizeClient(HttpEntity entity, IClientSecInfo clientInfo, IUser user)
        {
            //Validate client info
            _ = clientInfo ?? throw new ArgumentNullException(nameof(clientInfo));
            _ = clientInfo.PublicKey ?? throw new ArgumentException(nameof(clientInfo.PublicKey));
            _ = clientInfo.ClientId ?? throw new ArgumentException(nameof(clientInfo.ClientId));

            //Validate user
            _ = user ?? throw new ArgumentNullException(nameof(user));

            if (!entity.Session.IsSet || entity.Session.IsNew || entity.Session.SessionType != SessionType.Web)
            {
                throw new ArgumentException("The session is no configured for authorization");
            }

            //Generate the new client token for the client's public key
            ClientSecurityToken authTokens = GenerateToken(clientInfo.PublicKey);

            /*
             * Create thet login cookie value, we need to pass the initial user account
             * status for the user cookie. This is not required if the user is already
             * logged in
             */

            string loginCookie = SetLoginCookie(entity);
            SetClientStatusCookie(entity, user.IsLocalAccount());

            //Store the login hash in the user's session
            entity.Session.LoginHash = loginCookie;
            //Store the server token in the session
            entity.Session.Token = authTokens.ServerToken;

            /*
             * The user's public key will be stored via a jwt cookie
             * signed by this specific signing key, we will save the signing key
             * in the session
             */
            string base32Key = SetPublicKeyCookie(entity, clientInfo.PublicKey);
            entity.Session[PUBLIC_KEY_SIG_KEY_ENTRY] = base32Key;

            //Return the new authorzation
            return new Authorization()
            {
                LoginSecurityString = loginCookie,
                SecurityToken = authTokens,
            };
        }

        ///<inheritdoc/>
        void IAccountSecurityProvider.InvalidateLogin(HttpEntity entity)
        {
            //Client should also destroy the session
            ExpireCookies(entity);

            //Clear known security keys
            entity.Session.Token = null!;
            entity.Session.LoginHash = null!;
            entity.Session[PUBLIC_KEY_SIG_KEY_ENTRY] = null!;
        }

        ///<inheritdoc/>
        bool IAccountSecurityProvider.IsClientAuthorized(HttpEntity entity, AuthorzationCheckLevel level)
        {
            //Session must be loaded and not-new for an authorization to exist
            if(!entity.Session.IsSet || entity.Session.IsNew)
            {
                return false;
            }

            return level switch
            {
                //Accept the client token or the cookie as any/medium 
                AuthorzationCheckLevel.Any or AuthorzationCheckLevel.Medium => VerifyLoginCookie(entity) || VerifyClientToken(entity),
                //Critical requires that the client cookie is set and the token is set
                AuthorzationCheckLevel.Critical => VerifyLoginCookie(entity) && VerifyClientToken(entity),
                //Default to false condition
                _ => false,
            };
        }

        ///<inheritdoc/>
        IClientAuthorization IAccountSecurityProvider.ReAuthorizeClient(HttpEntity entity)
        {
            //Confirm session is configured
            if (!entity.Session.IsSet || entity.Session.IsNew || entity.Session.SessionType != SessionType.Web)
            {
                throw new InvalidOperationException ("The session is not configured for authorization");
            }

            //recover the client's public key
            if(!TryGetPublicKey(entity, out string? pubKey))
            {
                throw new InvalidOperationException("The user does not have the required public key token stored");
            }

            //Try to generate a new authorization
            ClientSecurityToken authTokens = GenerateToken(pubKey);

            //Set login cookies with stored session data
            string loginCookie = SetLoginCookie(entity);

            //Update the public key cookie
            string signingKey = SetPublicKeyCookie(entity, pubKey);
            //Store signing key
            entity.Session[PUBLIC_KEY_SIG_KEY_ENTRY] = signingKey;

            //Update token/login
            entity.Session.LoginHash = loginCookie;
            entity.Session.Token = authTokens.ServerToken;

            //Return the new authorzation
            return new Authorization()
            {
                LoginSecurityString = loginCookie,
                SecurityToken = authTokens,
            };
        }

        ///<inheritdoc/>
        ERRNO IAccountSecurityProvider.TryEncryptClientData(HttpEntity entity, ReadOnlySpan<byte> data, Span<byte> outputBuffer)
        {
            //Recover the signed public key, already does session checks
            return TryGetPublicKey(entity, out string? pubKey) ? TryEncryptClientData(pubKey, data, outputBuffer) : ERRNO.E_FAIL;
        }

        ///<inheritdoc/>
        ERRNO IAccountSecurityProvider.TryEncryptClientData(IClientSecInfo entity, ReadOnlySpan<byte> data, Span<byte> outputBuffer)
        {
            //Use the public key supplied by the csecinfo 
            return TryEncryptClientData(entity.PublicKey, data, outputBuffer);
        }

        #endregion

        #region Security Tokens

        /*
         * A client token was an older term used for a single random token generated
         * by the server and sent by the client.
         * 
         * The latest revision generates a keypair on authorization, the public key
         * is stored id the client's session, and the private key gets encrypted
         * and sent to the client. The client uses this ECDSA key to sign one time use
         * JWT tokens
         * 
         */

        private ClientSecurityToken GenerateToken(ReadOnlySpan<char> publicKey)
        {
            //Alloc buffer for encode/decode
            using IMemoryHandle<byte> buffer = MemoryUtil.SafeAllocNearestPage(4000, true);
            try
            {
                Span<byte> secretBuffer = buffer.Span[.._config.TokenKeySize];
                Span<byte> outputBuffer = buffer.Span[_config.TokenKeySize..];

                //Computes a random shared key
                RandomHash.GetRandomBytes(secretBuffer);

                ERRNO bytesEncrypted = TryEncryptClientData(publicKey, secretBuffer, outputBuffer);

                //Encyrpt the secret key to send to client
                if (!bytesEncrypted)
                {
                    throw new InternalBufferTooSmallException("The internal buffer used to store the encrypted token is too small");
                }

                //Convert the tokens to base64 encoding and return the new cst
                return new()
                {
                    //Client token is the encrypted private key
                    ClientToken = Convert.ToBase64String(outputBuffer[..(int)bytesEncrypted]),
                    //Server token is the raw secret
                    ServerToken = VnEncoding.ToBase32String(secretBuffer)
                };
            }
            finally
            {
                //Zero buffer when complete
                MemoryUtil.InitializeBlock(buffer.Span);
            }
        }

        private bool VerifyClientToken(HttpEntity entity)
        {
            //Get the token from the client header, the client should always sent this
            string? signedMessage = entity.Server.Headers[_config.TokenHeaderName];
         
            //Make sure a session is loaded
            if (!entity.Session.IsSet || entity.Session.IsNew || string.IsNullOrWhiteSpace(signedMessage))
            {
                return false;
            }

            //Get the stored shared symetric key
            string sharedKey = entity.Session.Token;
            if (string.IsNullOrWhiteSpace(sharedKey))
            {
                return false;
            }

            /*
             * The clients signed message is a json web token that includes basic information
             * Clients may send bad data, so we should swallow exceptions and return false
             */

            bool isValid = true;

            try
            {
                //Parse the client jwt signed message
                using JsonWebToken jwt = JsonWebToken.Parse(signedMessage);
               
                using (UnsafeMemoryHandle<byte> decodeBuffer = MemoryUtil.UnsafeAllocNearestPage(_config.TokenKeySize, true))
                {
                    //Recover the key from base32
                    ERRNO count = VnEncoding.TryFromBase32Chars(sharedKey, decodeBuffer.Span);

                    if (!count)
                    {
                        return false;
                    }

                    //Verity the jwt against the store symmetric key
                    isValid &= jwt.Verify(decodeBuffer.AsSpan(0, count), ClientTokenHmacType);
                }

                //Get the message payload
                using JsonDocument data = jwt.GetPayload();

                //Get iat time
                if (data.RootElement.TryGetProperty("iat", out JsonElement iatEl))
                {
                    //Try to get iat in uning seconds 
                    isValid &= iatEl.TryGetInt64(out long iatSec);
                    
                    //Recover dto from seconds
                    DateTimeOffset iat = DateTimeOffset.FromUnixTimeSeconds(iatSec);

                    //Verify iat against current time with allowed disparity
                    isValid &= iat.Add(_config.SignedTokenTimeDiff) > entity.RequestedTimeUtc;

                    //Message is too far into the future!
                    isValid &= iat.Subtract(_config.SignedTokenTimeDiff) < entity.RequestedTimeUtc;
                }
                else
                {
                    //No time element provided
                    isValid = false;
                }
            }
            catch (FormatException)
            {
                //we may catch the format exception for a malformatted jwt
                isValid = false;
            }
            
            return isValid;
        }
        
        #endregion

        #region Cookies
        
        private bool VerifyLoginCookie(HttpEntity entity)
        {
            //Sessions must be loaded
            if (!entity.Session.IsSet || entity.Session.IsNew)
            {
                return false;
            }

            //Try to get the login string from the request cookies
            if (!entity.Server.RequestCookies.TryGetNonEmptyValue(_config.LoginCookieName, out string? cookie))
            {
                return false;
            }

            //Make sure a login hash is stored
            if (string.IsNullOrWhiteSpace(entity.Session.LoginHash))
            {
                return false;
            }


            //Alloc buffer for decoding the base64 signatures
            using UnsafeMemoryHandle<byte> buffer = MemoryUtil.UnsafeAllocNearestPage(2 * _config.LoginCookieSize, true);

            //Slice up buffers 
            Span<byte> cookieBuffer = buffer.Span[.._config.LoginCookieSize];
            Span<byte> sessionBuffer = buffer.AsSpan(_config.LoginCookieSize, _config.LoginCookieSize);
            
            //Convert cookie and session hash value
            if (Convert.TryFromBase64Chars(cookie, cookieBuffer, out int cookieBytesWriten)
                && Convert.TryFromBase64Chars(entity.Session.LoginHash, sessionBuffer, out int hashBytesWritten))
            {
                //Do a fixed time equal (probably overkill, but should not matter too much)
                if (CryptographicOperations.FixedTimeEquals(cookieBuffer[..cookieBytesWriten], sessionBuffer[..hashBytesWritten]))
                {
                    return true;
                }
            }
            //Clear login cookie if failed
            ExpireCookies(entity);
            return false;
        }

        private void ExpireCookies(HttpEntity entity)
        {
            //Expire login cookie if set
            if (entity.Server.RequestCookies.ContainsKey(_config.LoginCookieName))
            {
                _cookieHandler.ExpireCookie(entity, _config.LoginCookieName);
            }

            //Expire the LI cookie if set
            if (entity.Server.RequestCookies.ContainsKey(_config.ClientStatusCookieName))
            {
                _cookieHandler.ExpireCookie(entity, _config.ClientStatusCookieName);
            }

            //Expire pupkey cookie
            if (entity.Server.RequestCookies.ContainsKey(_config.PubKeyCookieName))
            {
                _cookieHandler.ExpireCookie(entity, _config.PubKeyCookieName);
            }
        }

        #endregion

        #region Data Encryption

        /// <summary>
        /// Tries to encrypt the specified data using the specified public key
        /// </summary>
        /// <param name="base64PubKey">A base64 encoded public key used to encrypt client data</param>
        /// <param name="data">Data to encrypt</param>
        /// <param name="outputBuffer">The buffer to store encrypted data in</param>
        /// <returns>
        /// The number of encrypted bytes written to the output buffer,
        /// or false (0) if the operation failed, or if no credential is 
        /// specified.
        /// </returns>
        /// <exception cref="CryptographicException"></exception>
        private static ERRNO TryEncryptClientData(ReadOnlySpan<char> base64PubKey, ReadOnlySpan<byte> data, Span<byte> outputBuffer)
        {
            if (base64PubKey.IsEmpty)
            {
                return ERRNO.E_FAIL;
            }

            //Alloc a buffer for decoding the public key
            using UnsafeMemoryHandle<byte> pubKeyBuffer = MemoryUtil.UnsafeAllocNearestPage(base64PubKey.Length, true);

            //Decode the public key
            ERRNO pbkBytesWritten = VnEncoding.TryFromBase64Chars(base64PubKey, pubKeyBuffer.Span);

            //Try to encrypt the data
            return pbkBytesWritten ? TryEncryptClientData(pubKeyBuffer.Span[..(int)pbkBytesWritten], data, outputBuffer) : ERRNO.E_FAIL;
        }

        /// <summary>
        /// Tries to encrypt the specified data using the specified public key
        /// </summary>
        /// <param name="rawPubKey">The raw SKI public key</param>
        /// <param name="data">Data to encrypt</param>
        /// <param name="outputBuffer">The buffer to store encrypted data in</param>
        /// <returns>
        /// The number of encrypted bytes written to the output buffer,
        /// or false (0) if the operation failed, or if no credential is 
        /// specified.
        /// </returns>
        /// <exception cref="CryptographicException"></exception>
        private static ERRNO TryEncryptClientData(ReadOnlySpan<byte> rawPubKey, ReadOnlySpan<byte> data, Span<byte> outputBuffer)
        {
            if (rawPubKey.IsEmpty)
            {
                return false;
            }

            //Setup new empty rsa
            using RSA rsa = RSA.Create();

            //Import the public key
            rsa.ImportSubjectPublicKeyInfo(rawPubKey, out _);

            //Encrypt data with OaepSha256 as configured in the browser
            return rsa.TryEncrypt(data, outputBuffer, ClientEncryptonPadding, out int bytesWritten) ? bytesWritten : ERRNO.E_FAIL;
        }
        
        #endregion

        /// <summary>
        /// Stores the login key as a cookie in the current session as long as the session exists
        /// </summary>/
        /// <param name="ev">The event to log-in</param>
        /// <param name="localAccount">Does the session belong to a local user account</param>
        private string SetLoginCookie(HttpEntity ev)
        {
            //Get the new random cookie value
            string loginString = RandomHash.GetRandomBase64(_config.LoginCookieSize);

            //Set the cookie for the login key
            _cookieHandler.SetCookie(ev, _config.LoginCookieName, loginString, true);

            return loginString;
        }

        private void SetClientStatusCookie(HttpEntity entity, bool? localAccount = null)
        {
            //If not set get from session storage
            localAccount ??= entity.Session.HasLocalAccount();

            //set client status cookie via handler
            _cookieHandler.SetCookie(entity, _config.ClientStatusCookieName, localAccount.Value ? "1" : "2", false);
        }

        #region Client Encryption Key

        /*
         * Stores the public key the client provided as a signed JWT a and sets
         * it as a cookie in the user's browser.
         * 
         * The signing key is randomly generated and stored in the client's session
         * so it cannot "stolen"
         * 
         * This was done mostly to save session storage space
         */

        private string SetPublicKeyCookie(HttpEntity entity, string pubKey)
        {
            //generate a random nonce
            string nonce = RandomHash.GetRandomHex(PUB_KEY_JWT_NONCE_SIZE);

            //Generate signing key
            using JsonWebToken jwt = new();
            //No header to write, we know the format
            
            //add the clients public key and set iat/exp 
            jwt.InitPayloadClaim()
                .AddClaim("sub", pubKey)
                .AddClaim("iat", entity.RequestedTimeUtc.ToUnixTimeSeconds())
                .AddClaim("exp", entity.RequestedTimeUtc.Add(_config.AuthorizationValidFor).ToUnixTimeSeconds())
                .AddClaim("nonce", nonce)
                .CommitClaims();

            //genreate random signing key to store in the user's session
            byte[] signingKey = RandomHash.GetRandomBytes(_config.PubKeySigningKeySize);

            //Sign jwt
            jwt.Sign(signingKey, ClientTokenHmacType);

            //base32 encode the signing key 
            string base32SigningKey = VnEncoding.ToBase32String(signingKey, false);

            //Zero signing key now were done using it
            MemoryUtil.InitializeBlock(signingKey.AsSpan());

            //Compile the jwt for the cookie value
            string jwtValue = jwt.Compile();

            _cookieHandler.SetCookie(entity, _config.PubKeyCookieName, jwtValue, true);

            //Return the signing key
            return base32SigningKey;
        }

        private bool TryGetPublicKey(HttpEntity entity, [NotNullWhen(true)] out string? pubKey)
        {
            pubKey = null;

            //Check session is valid for use
            if (!entity.Session.IsSet || entity.Session.IsNew || entity.Session.SessionType != SessionType.Web)
            {
                return false;
            }

            //Get the jwt cookie
            string? pubKeyJwt = _cookieHandler.GetCookie(entity, _config.PubKeyCookieName);
           
            if (string.IsNullOrWhiteSpace(pubKeyJwt))
            {
                return false;
            }

            //Get the client signature
            string? base32Sig = entity.Session[PUBLIC_KEY_SIG_KEY_ENTRY];

            if (string.IsNullOrWhiteSpace(base32Sig))
            {
                return false;
            }

            //Parse the jwt
            using JsonWebToken jwt = JsonWebToken.Parse(pubKeyJwt);

            //Recover the signing key bytes
            byte[] signingKey = VnEncoding.FromBase32String(base32Sig)!;

            //verify the client signature
            if (!jwt.Verify(signingKey, ClientTokenHmacType))
            {
                return false;
            }

            //Verify expiration
            using JsonDocument payload = jwt.GetPayload();

            //Get the expiration time from the jwt
            long expTimeSec = payload.RootElement.GetProperty("exp").GetInt64();
            DateTimeOffset expired = DateTimeOffset.FromUnixTimeSeconds(expTimeSec);

            //Check if expired
            if (expired.Ticks < entity.RequestedTimeUtc.Ticks)
            {
                return false;
            }

            //Store the public key
            pubKey = payload.RootElement.GetProperty("sub").GetString()!;

            return true;
        }
       
        #endregion


        private sealed class AccountSecConfig : IOnConfigValidation
        {
            private static IValidator<AccountSecConfig> _validator { get; } = GetValidator();

            private static IValidator<AccountSecConfig> GetValidator()
            {
                InlineValidator<AccountSecConfig> val = new();

                val.RuleFor(c => c.LoginCookieName)
                    .Length(1, 50)
                    .IllegalCharacters();

                val.RuleFor(c => c.LoginCookieSize)
                    .InclusiveBetween(8, 4096)
                    .WithMessage("The login cookie size must be a sensable value between 8 bytes and 4096 bytes long");

                //Cookie domain may be null/emmpty
                val.RuleFor(c => c.CookieDomain);

                //Cookie path may be empty or null
                val.RuleFor(c => c.CookiePath);

                val.RuleFor(c => c.AuthorizationValidFor)
                   .GreaterThan(TimeSpan.FromMinutes(1))
                   .WithMessage("The authorization should be valid for at-least 1 minute");

                val.RuleFor(C => C.ClientStatusCookieName)
                   .Length(1, 50)
                   .AlphaNumericOnly();

                //header name is required, but not allowed to contain "illegal" chars
                val.RuleFor(c => c.TokenHeaderName)
                    .NotEmpty()
                    .IllegalCharacters();


                val.RuleFor(c => c.PubKeyCookieName)
                    .Length(1, 50)
                    .IllegalCharacters();

                //Signing keys are base32 encoded and stored in the session, we dont want to take up too much space
                val.RuleFor(c => c.PubKeySigningKeySize)
                    .InclusiveBetween(8, 512)
                    .WithMessage("Your public key signing key should be between 8 and 512 bytes");

                //Time difference doesnt need to be validated, it may be 0 to effectively disable it
                val.RuleFor(c => c.SignedTokenTimeDiff);

                val.RuleFor(c => c.TokenKeySize)
                    .InclusiveBetween(8, 512)
                    .WithMessage("You should choose an OTP symmetric key size between 8 and 512 bytes");

                return val;
            }

            /// <summary>
            /// The name of the random security cookie
            /// </summary>
            [JsonPropertyName("login_cookie_name")]
            public string LoginCookieName { get; set; } = "VNLogin";

            /// <summary>
            /// The size (in bytes) of the randomly generated security cookie
            /// </summary>
            [JsonPropertyName("login_cookie_size")]
            public int LoginCookieSize { get; set; } = 64;

            /// <summary>
            /// The domain all authoization cookies will be set for
            /// </summary>
            [JsonPropertyName("cookie_domain")]
            public string CookieDomain { get; set; } = "";

            /// <summary>
            /// The path all authorization cookies will be set for
            /// </summary>
            [JsonPropertyName("cookie_path")]
            public string? CookiePath { get; set; } = "/";

            /// <summary>
            /// The amount if time new authorizations are valid for. This also 
            /// sets the duration of client cookies.
            /// </summary>
            [JsonIgnore]
            internal TimeSpan AuthorizationValidFor { get; set; } = TimeSpan.FromMinutes(60);

            /// <summary>
            /// The name of the cookie used to set the client's login status message
            /// </summary>
            [JsonPropertyName("status_cookie_name")]
            public string ClientStatusCookieName { get; set; } = "li";

            /// <summary>
            /// The name of the header used by the client to send the one-time use
            /// authorization token
            /// </summary>
            [JsonPropertyName("otp_header_name")]
            public string TokenHeaderName { get; set; } = "X-Web-Token";

            /// <summary>
            /// The size (in bytes) of the symmetric key used
            /// by the client to sign token messages
            /// </summary>
            [JsonPropertyName("otp_key_size")]
            public int TokenKeySize { get; set; } = 64;

            /// <summary>
            /// The name of the cookie that stores the user's signed public encryption key
            /// </summary>
            [JsonPropertyName("pubkey_cookie_name")]
            public string PubKeyCookieName { get; set; } = "client_id";

            /// <summary>
            /// The size (in bytes) of the randomly generated key
            /// used to sign the user's public key 
            /// </summary>
            [JsonPropertyName("pubkey_signing_key_size")]
            public int PubKeySigningKeySize { get; set; } = 32;

            /// <summary>
            /// The allowed time difference in the issuance time of the client's signed
            /// one time use tokens
            /// </summary>
            [JsonIgnore]
            internal TimeSpan SignedTokenTimeDiff { get; set; } = TimeSpan.FromSeconds(30);

            [JsonPropertyName("otp_time_diff_sec")]
            public uint SigTokenTimeDifSeconds
            {
                get => (uint)SignedTokenTimeDiff.TotalSeconds;
                set => SignedTokenTimeDiff = TimeSpan.FromSeconds(value);
            }

            void IOnConfigValidation.Validate()
            {
                //Validate the current instance
                _validator.ValidateAndThrow(this);
            }
        }

        private sealed class Authorization : IClientAuthorization
        {
            ///<inheritdoc/>
            public string? LoginSecurityString { get; init; }

            ///<inheritdoc/>
            public ClientSecurityToken SecurityToken { get; init; }
        }

        record class CookieHandler(AccountSecConfig Config)
        {

            /// <summary>
            /// Expires a cookie with the given name
            /// </summary>
            /// <param name="entity">The entity to expire the cookie on</param>
            /// <param name="cookieName">The name of the cookie to expire</param>
            public void ExpireCookie(HttpEntity entity, string cookieName)
            {
                HttpCookie cookie = new(cookieName, string.Empty)
                {
                    Domain = Config.CookieDomain,
                    Path = Config.CookiePath,
                    ValidFor = TimeSpan.Zero,
                    SameSite = CookieSameSite.SameSite,
                    HttpOnly = true,
                    Secure = true
                };

                entity.Server.SetCookie(in cookie);
            }

            /// <summary>
            /// Sets a cookie with the given name and value
            /// </summary>
            /// <param name="entity">The entity to set the cookie on</param>
            /// <param name="name">The name of the cookie to set</param>
            /// <param name="value">The value of the cookie to set</param>
            /// <param name="httpOnly">A value that indicates of the httponly flag should be set on the cookie</param>
            public void SetCookie(HttpEntity entity, string name, string value, bool httpOnly)
            {
                HttpCookie cookie = new(name, value)
                {
                    Domain = Config.CookieDomain,
                    Path = Config.CookiePath,
                    ValidFor = Config.AuthorizationValidFor,
                    SameSite = CookieSameSite.SameSite,
                    HttpOnly = httpOnly,
                    Secure = true
                };
                entity.Server.SetCookie(in cookie);
            }

            /// <summary>
            /// Gets the value of a cookie with the given name
            /// </summary>
            /// <param name="entity">The entity to get the cookie from</param>
            /// <param name="name">The name of the cooke to retrieve</param>
            /// <returns>The cookie value if found, null otherwise</returns>
            public string? GetCookie(HttpEntity entity, string name)
            {
                _ = entity.Server.GetCookie(name, out string? value);
                return value;
            }
        }
    }
}
