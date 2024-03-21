/*
* Copyright (c) 2024 Vaughn Nugent
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
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using System.Diagnostics.CodeAnalysis;

using FluentValidation;

using VNLib.Hashing;
using VNLib.Hashing.IdentityUtility;
using VNLib.Net.Http;
using VNLib.Utils;
using VNLib.Utils.Memory;
using VNLib.Utils.Logging;
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
    [MiddlewareImpl(MiddlewareImplOptions.SecurityCritical)]
    internal sealed class AccountSecProvider : IAccountSecurityProvider, IHttpMiddleware
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
        private readonly SingleCookieController _statusCookie;
        private readonly SingleCookieController _pubkeyCookie;
        private readonly ILogProvider _logger;

        public AccountSecProvider(PluginBase plugin)
            :this(plugin, new AccountSecConfig())
        { }

        public AccountSecProvider(PluginBase plugin, IConfigScope config)
            :this(
                 plugin,
                 config.DeserialzeAndValidate<AccountSecConfig>()
            )
        { }

        private AccountSecProvider(PluginBase plugin, AccountSecConfig config)
        {
            //Parse config if defined
            _config = config;

            //Status cookie handler
            _statusCookie = new(_config.ClientStatusCookieName, _config.AuthorizationValidFor)
            {
                Domain = _config.CookieDomain,
                Path = _config.CookiePath,
                SameSite = CookieSameSite.Strict,
                HttpOnly = false,   //allow javascript to read this cookie
                Secure = true
            };

            //Public key cookie handler
            _pubkeyCookie = new(_config.PubKeyCookieName, _config.AuthorizationValidFor)
            {
                Domain = _config.CookieDomain,
                Path = _config.CookiePath,
                SameSite = CookieSameSite.Strict,
                HttpOnly = true,
                Secure = true
            };

            _logger = plugin.Log.CreateScope("Acnt-Sec");
        }

        /*
         * Middleware handler for reconciling client cookies for all connections
         */

        ///<inheritdoc/>
        ValueTask<FileProcessArgs> IHttpMiddleware.ProcessAsync(HttpEntity entity)
        {

            ref readonly SessionInfo session = ref entity.Session;

            //Session must be set and web based for checks
            if (session.IsSet && session.SessionType == SessionType.Web)
            {
                //Make sure the session has not expired yet                
                if (OnMwCheckSessionExpired(entity, in session))
                {
                    //Expired
                    ExpireCookies(entity, true);
                    
                    //Verbose because this is a normal occurance
                    if (_logger.IsEnabled(LogLevel.Verbose))
                    {
                        _logger.Verbose("Session {id} expired", session.SessionID[..8]);
                    }
                }
                else
                {
                    //See if the session might be elevated
                    if (!string.IsNullOrWhiteSpace(session.Token))
                    {
                        //If the session stored a user-agent, make sure it matches the connection
                        if (session.UserAgent != null && !session.UserAgent.Equals(entity.Server.UserAgent, StringComparison.Ordinal))
                        {
                            _logger.Debug("Denied authorized connection from {ip} because user-agent changed", entity.TrustedRemoteIp);
                            return ValueTask.FromResult(FileProcessArgs.Deny);
                        }
                    }

                    //If the session is new, or not supposed to be logged in, clear the login cookies if they were set
                    if (session.IsNew || string.IsNullOrEmpty(session.Token))
                    {
                        ExpireCookies(entity, false);
                    }
                }
            }

            //Always continue otherwise
            return ValueTask.FromResult(FileProcessArgs.Continue);
        }

        /*
         * Verify sessions on new connections to ensure they have not expired 
         * and need to be regnerated or invalidated. If they are expired
         * we need to cleanup any internal security flags/keys
         */
        private bool OnMwCheckSessionExpired(HttpEntity entity, ref readonly SessionInfo session)
        {
            if (session.Created.AddSeconds(_config.WebSessionValidForSeconds) < entity.RequestedTimeUtc)
            {
                //Invalidate the session, so its technically valid for this request, but will be cleared on this handle close cycle
                session.Invalidate();

                //Clear basic login status now so checks will fail later
                session.Token = null!;
                session.UserID = null!;
                session.Privilages = 0;
                session[PUBLIC_KEY_SIG_KEY_ENTRY] = null!;

                return true;
            }

            //Not expired
            return false;
        }

        #region Interface Impl

        ///<inheritdoc/>
        IClientAuthorization IAccountSecurityProvider.AuthorizeClient(HttpEntity entity, IClientSecInfo clientInfo, IUser user)
        {
            //Validate client info
            ArgumentNullException.ThrowIfNull(user);
            ArgumentNullException.ThrowIfNull(clientInfo);
            ArgumentNullException.ThrowIfNull(clientInfo.PublicKey, nameof(clientInfo.PublicKey));
            ArgumentNullException.ThrowIfNull(clientInfo.ClientId, nameof(clientInfo.ClientId));

            if (!entity.Session.IsSet || entity.Session.IsNew || entity.Session.SessionType != SessionType.Web)
            {
                throw new ArgumentException("The session is no configured for authorization");
            }

            return GenerateAuth(entity, clientInfo.PublicKey, user.IsLocalAccount());
        }

        ///<inheritdoc/>
        IClientAuthorization IAccountSecurityProvider.ReAuthorizeClient(HttpEntity entity)
        {
            //Confirm session is configured
            if (!entity.Session.IsSet || entity.Session.IsNew || entity.Session.SessionType != SessionType.Web)
            {
                throw new InvalidOperationException("The session is not configured for authorization");
            }

            //recover the client's public key
            if (!TryGetPublicKey(entity, out string? pubKey))
            {
                throw new InvalidOperationException("The user does not have the required public key token stored");
            }

            return GenerateAuth(entity, pubKey, entity.Session.HasLocalAccount());
        }

        ///<inheritdoc/>
        void IAccountSecurityProvider.InvalidateLogin(HttpEntity entity)
        {
            //Client should also destroy the session
            ExpireCookies(entity, true);

            //Clear known security keys
            entity.Session.Token = null!;
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
                AuthorzationCheckLevel.Any or AuthorzationCheckLevel.Medium => VerifyClientToken(entity) || TryGetPublicKey(entity, out _),
                //Critical requires that the client cookie is set and the token is set
                AuthorzationCheckLevel.Critical => TryGetPublicKey(entity, out _) && VerifyClientToken(entity),
                //Default to false condition
                _ => false,
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

        private IClientAuthorization GenerateAuth(HttpEntity entity, string publicKey, bool localAccount)
        {
            //Try to generate a new authorization
            GenerateToken(publicKey, out string serverToken, out string clientToken);

            /*
            * The user's public key will be stored via a jwt cookie
            * signed by this specific signing key, we will save the signing key
            * in the session
            */
            entity.Session[PUBLIC_KEY_SIG_KEY_ENTRY] = SetPublicKeyCookie(entity, publicKey);
            entity.Session.Token = serverToken;

            //set client status cookie via handler
            _statusCookie.SetCookie(entity, localAccount ? "1" : "2");

            //Return the new authorzation
            return new EncryptedTokenAuthorization(clientToken);
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

        private void GenerateToken(ReadOnlySpan<char> publicKey, out string serverToken, out string clientToken)
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
                
                //Client token is the encrypted secret key
                clientToken = Convert.ToBase64String(outputBuffer[..(int)bytesEncrypted]);

                //Encode base64 url safe
                serverToken = VnEncoding.ToBase64UrlSafeString(secretBuffer, false);
            }
            finally
            {
                //Zero buffer when complete
                MemoryUtil.InitializeBlock(ref buffer.GetReference(), buffer.GetIntLength());
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

            try
            {
                bool isValid = true;

                //Parse the client jwt signed message
                using JsonWebToken jwt = JsonWebToken.Parse(signedMessage);
               
                using (UnsafeMemoryHandle<byte> decodeBuffer = MemoryUtil.UnsafeAllocNearestPage(_config.TokenKeySize, true))
                {
                    //Recover the key from base32
                    ERRNO count = VnEncoding.Base64UrlDecode(sharedKey, decodeBuffer.Span);

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
                if (data.RootElement.TryGetProperty("iat", out JsonElement iatEl) 
                    && iatEl.ValueKind == JsonValueKind.Number)
                {
                    //Try to get iat in unint seconds 
                    isValid &= iatEl.TryGetInt64(out long iatSec);
                    
                    //Recover dto from unix seconds regardless of int success
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

                if (_config.VerifyOrigin)
                {
                    //Check the audience matches the request uri
                    if (data.RootElement.TryGetProperty("aud", out JsonElement tokenOriginEl)
                        && tokenOriginEl.ValueKind == JsonValueKind.String)
                    {
                        string? unsafeUserOrigin = tokenOriginEl.GetString();

                        if(string.IsNullOrWhiteSpace(unsafeUserOrigin))
                        {
                            isValid = false;
                        }
                        else if (_config.EnforceSameOriginToken)
                        {
                            //enforce strict origin checking
                            string strictOrigin = entity.Server.RequestUri.GetLeftPart(UriPartial.Authority);
                            isValid &= string.Equals(unsafeUserOrigin, strictOrigin, StringComparison.OrdinalIgnoreCase);

                            if (!isValid)
                            {
                                _logger.Debug("Client security OTP JWT origin mismatch from {ip} : strict origin {current} != {token}",
                                    entity.TrustedRemoteIp,
                                    strictOrigin,
                                    unsafeUserOrigin
                                );
                            }
                        }
                        else
                        {
                            //Verify against allow list
                            isValid &= _config.AllowedOrigins!.Contains(unsafeUserOrigin, StringComparer.OrdinalIgnoreCase);

                            if (!isValid)
                            {
                                _logger.Debug("CST origin not allowed {ip} : {token}",
                                    entity.TrustedRemoteIp,
                                    unsafeUserOrigin
                                );
                            }
                        }
                    }
                    else
                    {
                        isValid = false;
                    }
                }

                if (_config.VerifyPath)
                {
                    //Check the subject (path) matches the request uri
                    if (data.RootElement.TryGetProperty("path", out JsonElement tokenPathEl)
                        && tokenPathEl.ValueKind == JsonValueKind.String)
                    {

                        ReadOnlySpan<char> unsafeUserPath = tokenPathEl.GetString();
                        /*
                         * Query parameters are optional, so we need to check if the path contains a 
                         * query, if so we can compare the entire path and query, otherwise we need to
                         * compare the path only
                         */
                        if (unsafeUserPath.Contains("?", StringComparison.OrdinalIgnoreCase))
                        {
                            //Compare path and query when possible
                            string requestPath = entity.Server.RequestUri.PathAndQuery;

                            isValid &= unsafeUserPath.Equals(requestPath, StringComparison.OrdinalIgnoreCase);

                            if (!isValid && _logger.IsEnabled(LogLevel.Debug))
                            {
                                _logger.Debug("Client security OTP JWT path mismatch from {ip} : {current} != {token}",
                                  entity.TrustedRemoteIp,
                                  requestPath,
                                  unsafeUserPath.ToString()
                                );
                            }
                        }
                        else
                        {
                            //Use path only
                            string requestPath = entity.Server.RequestUri.LocalPath;

                            //Compare path only
                            isValid &= unsafeUserPath.Equals(requestPath, StringComparison.OrdinalIgnoreCase);

                            if (!isValid && _logger.IsEnabled(LogLevel.Debug))
                            {
                                _logger.Debug("Client security OTP JWT path mismatch from {ip} : {current} != {token}",
                                    entity.TrustedRemoteIp,
                                    requestPath,
                                    unsafeUserPath.ToString()
                                );
                            }
                        }
                    }
                    else
                    {
                        isValid = false;
                    }
                }

                return isValid;
            }
            catch (FormatException)
            {
                //we may catch the format exception for a malformatted jwt
                _logger.Debug("Client security OTP JWT not valid from {ip}", entity.TrustedRemoteIp);
                return false;
            }
        }
        
        #endregion

        #region Cookies

        private void ExpireCookies(HttpEntity entity, bool force)
        {
            //Do not force clear cookies (saves bandwidth)
            _statusCookie.ExpireCookie(entity, force);
            _pubkeyCookie.ExpireCookie(entity, force);
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
            MemoryUtil.InitializeBlock(signingKey);

            //Compile the jwt for the cookie value
            string jwtValue = jwt.Compile();

            _pubkeyCookie.SetCookie(entity, jwtValue);

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
            string? pubKeyJwt = _pubkeyCookie.GetCookie(entity);
           
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

            try
            {

                //Parse the jwt
                using JsonWebToken jwt = JsonWebToken.Parse(pubKeyJwt);

                //Recover the signing key bytes
                byte[] signingKey = VnEncoding.FromBase32String(base32Sig)!;

                //verify the client signature
                if (!jwt.Verify(signingKey, ClientTokenHmacType))
                {
                    return false;
                }

                //Erase the signing key bytes
                MemoryUtil.InitializeBlock(signingKey);

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
            catch (FormatException)
            {
                //JWT is invalid and could not be parsed
                _logger.Debug("Client public key JWT or message body was not valid from {ip}", entity.TrustedRemoteIp);
            }

            return false;
        }
       
        #endregion


        private sealed class AccountSecConfig : IOnConfigValidation
        {
            private static IValidator<AccountSecConfig> _validator { get; } = GetValidator();

            private static IValidator<AccountSecConfig> GetValidator()
            {
                InlineValidator<AccountSecConfig> val = new();

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

                val.RuleFor(c => c.WebSessionValidForSeconds)
                    .InclusiveBetween((uint)1, uint.MaxValue)
                    .WithMessage("You must specify a valid value for a web session timeout in seconds");

                val.RuleForEach(c => c.AllowedOrigins)
                    .Matches(@"^https?://[a-z0-9\-\.]+$")
                    .WithMessage("The allowed origins must be valid http(s) urls");

                return val;
            }

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

            /// <summary>
            /// The amount of time a web session is valid for
            /// </summary>
            [JsonPropertyName("session_valid_for_sec")]
            public uint WebSessionValidForSeconds { get; set; } = 3600;

            [JsonPropertyName("otp_time_diff_sec")]
            public uint SigTokenTimeDifSeconds
            {
                get => (uint)SignedTokenTimeDiff.TotalSeconds;
                set => SignedTokenTimeDiff = TimeSpan.FromSeconds(value);
            }

            /// <summary>
            /// Enforce that the client's token is only valid for the origin 
            /// it was read from. Will break sites hosted from multiple origins
            /// </summary>
            [JsonPropertyName("strict_origin")]
            public bool EnforceSameOriginToken { get; set; } = true;

            /// <summary>
            /// Enable/disable origin verification for the client's token
            /// </summary>
            [JsonIgnore]
            public bool VerifyOrigin => AllowedOrigins != null && AllowedOrigins.Length > 0;

            /// <summary>
            /// The list of origins that are allowed to send requests to the server
            /// </summary>
            [JsonPropertyName("allowed_origins")]
            public string[]? AllowedOrigins { get; set; }

            /// <summary>
            /// Enforce strict path checking for the client's token
            /// </summary>
            [JsonPropertyName("strict_path")]
            public bool VerifyPath { get; set; } = true;

            void IOnConfigValidation.Validate()
            {
                //Validate the current instance
                _validator.ValidateAndThrow(this);
            }
        }

        private sealed class EncryptedTokenAuthorization(string ClientAuthToken) : IClientAuthorization
        {
            ///<inheritdoc/>
            public object GetClientAuthData() => ClientAuthToken;

            ///<inheritdoc/>
            public string GetClientAuthDataString() => ClientAuthToken;            
        }
        
    }
}
