/*
* Copyright (c) 2025 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: ClientWebAuthManager.cs 
*
* ClientWebAuthManager.cs is part of VNLib.Plugins.Essentials.Accounts which is 
* part of the larger VNLib collection of libraries and utilities.
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
using System.Diagnostics;

using VNLib.Hashing;
using VNLib.Hashing.IdentityUtility;
using VNLib.Net.Http;
using VNLib.Utils;
using VNLib.Utils.Memory;
using VNLib.Utils.Logging;
using VNLib.Utils.Extensions;
using VNLib.Plugins.Essentials.Sessions;
using VNLib.Plugins.Essentials.Extensions;

namespace VNLib.Plugins.Essentials.Accounts.SecurityProvider
{
    internal sealed class ClientWebAuthManager(AccountSecConfig config, ILogProvider logger)
    {
        const string PUBLIC_KEY_SIG_KEY_ENTRY = "acnt.pbsk";
        const string LOGIN_TOKEN_ENTRY = "acnt.lgk";
        const int PUB_KEY_JWT_NONCE_SIZE = 16;
        const HashAlg ClientTokenHmacType = HashAlg.SHA256;

        private readonly AccountSecConfig _config = config;
        private readonly ILogProvider _logger = logger;
        private readonly SingleCookieController _pubkeyCookie = new (config.PubKeyCookieName, config.AuthorizationValidFor)
        {
            Domain = config.CookieDomain,
            Path = config.CookiePath,
            SameSite = CookieSameSite.Strict,
            HttpOnly = true,
            Secure = true
        };

        /// <summary>
        /// Destroys the connection's authorization and session
        /// </summary>
        /// <param name="entity">The connection to destroy authorization data for</param>
        public void DestroyAuthorization(HttpEntity entity)
        {
            entity.Session.UserID = null!;
            entity.Session.Privilages = 0;

            SetLoginToken(in entity.Session, null);
            SetSigningKey(in entity.Session, null);

            _pubkeyCookie.ExpireCookie(entity, true);
        }

        /// <summary>
        /// Attempts to regenerate the authorization data for the connection 
        /// using existing credentials. This function does not test the
        /// existing authorization status, it assumes the connection is
        /// authorized already.
        /// </summary>
        /// <param name="entity">The connection to re-authorize</param>
        /// <param name="clientAuthData">The authentication data to return to the client</param>
        /// <returns>True if the connection could be reauthorized, false otherwise</returns>
        public bool TryReAuthorizeConnection(HttpEntity entity, ref string clientAuthData)
        {
            ClientAuthData cad = default;

            if (!TryGetSavedAuthData(entity, ref cad))
            {
                return false;
            }

            //Generate the authorization data
            clientAuthData = AuthorizeConnection(entity, ref cad);

            return true;
        }

        /// <summary>
        /// Expires all authorization related cookies for the connection
        /// </summary>
        /// <param name="entity">The entity to clear cookies from</param>
        /// <param name="force">A value that indicates whether the cookie should be sent to the client even if it isnt set</param>
        public void ExpireCookies(HttpEntity entity, bool force) => _pubkeyCookie.ExpireCookie(entity, force);

        /// <summary>
        /// Verifies the client's connection OTP token header to ensure the connection 
        /// is authorized.
        /// </summary>
        /// <param name="entity">The connection to verify</param>
        /// <returns>True if the connection is authorized or false otherwise</returns>
        public bool VerifyConnectionOTP(HttpEntity entity)
        {
            ClientAuthData cad = default;

            /*
             * When calling TryGetSavedAuthData() it ensures the client 
             * has a valid, signed, client auth data in its session.
             * 
             * Second we can verify the client's OTP token sent in 
             * a header to ensure the client.
             * 
             * The header should be a valid JWT signed with the shared 
             * key sent during authorization
             */
            return TryGetSavedAuthData(entity, ref cad) && VerifyConnectionOTPInternal(entity);
        }

        /// <summary>
        /// Determines if the connection has minimal auhtorization and should be 
        /// able to check for a higher level of authorization
        /// </summary>
        /// <param name="entity">The connection to verify</param>
        /// <returns>A value that indicates if the connection has a minimal authorization status</returns>
        public bool HasMinimalAuthorization(HttpEntity entity)
        {
            ClientAuthData cad = default;
            return TryGetSavedAuthData(entity, ref cad);
        }

        /// <summary>
        /// Upgrades the desired connection using the provided security information
        /// </summary>
        /// <param name="entity">The connection to upgrade</param>
        /// <param name="authData">The client's security information used for the upgrade</param>
        /// <returns>The encoded data to return to the client</returns>
        public string AuthorizeConnection(HttpEntity entity, ref readonly ClientAuthData authData)
        {
            string serverToken = string.Empty;
            string clientToken = string.Empty;
            string encodedSigKey = string.Empty;
            string pubkeyCookieValue = string.Empty;

            //Generate the authorization data
            GenerateToken(in authData, ref serverToken, ref clientToken);
            GenerateClientAuthCookie(in authData, entity, ref pubkeyCookieValue, ref encodedSigKey);

            //Upgrade the connection and session
            SetLoginToken(in entity.Session, serverToken);
            SetSigningKey(in entity.Session, encodedSigKey);
            SetPubkeyCookie(entity, pubkeyCookieValue);

            return clientToken;
        }

        /// <summary>
        /// Attempts to recover the client's encryption public key from the connection
        /// used to encrypt client data
        /// </summary>
        /// <param name="entity">The connection to recover the public key from</param>
        /// <param name="pubkey">A reference to the public key string</param>
        /// <returns>A value that indicates if the public key could be recovered</returns>
        public bool TryGetEncryptionPubkey(HttpEntity entity, ref string pubkey)
        {
            ClientAuthData cad = default;

            if (!TryGetSavedAuthData(entity, ref cad))
            {
                return false;
            }

            pubkey = cad.PublicKey;
            return true;
        }

        private void GenerateToken(ref readonly ClientAuthData secInfo, ref string serverToken, ref string clientToken)
        {
            //Alloc buffer for encode/decode
            using UnsafeMemoryHandle<byte> buffer = MemoryUtil.UnsafeAllocNearestPage(4000, true);
            try
            {
                Span<byte> secretBuffer = buffer.Span[.._config.TokenKeySize];
                Span<byte> outputBuffer = buffer.Span[_config.TokenKeySize..];

                //Computes a random shared key
                RandomHash.GetRandomBytes(secretBuffer);

                ERRNO bytesEncrypted = RsaClientDataEncryption.TryEncrypt(secInfo.PublicKey, secretBuffer, outputBuffer);

                //Encyrpt the secret key to send to client
                if (!bytesEncrypted)
                {
                    throw new InternalBufferTooSmallException("The internal buffer used to store the encrypted token is too small");
                }

                //Client token is the encrypted secret key
                clientToken = Convert.ToBase64String(outputBuffer[..(int)bytesEncrypted]);

                //Encode base64 url safe
                serverToken = VnEncoding.Base64UrlEncode(secretBuffer, includePadding: false);
            }
            finally
            {
                //Zero buffer when complete
                MemoryUtil.InitializeBlock(ref buffer.GetReference(), buffer.GetIntLength());
            }
        }

        /*
         * Stores the public key the client provided as a signed JWT a and sets
         * it as a cookie in the user's browser.
         * 
         * The signing key is randomly generated and stored in the client's session
         * so it cannot "stolen"
         * 
         * This was done mostly to save session storage space
         */

        private void GenerateClientAuthCookie(ref readonly ClientAuthData secInfo, HttpEntity entity, ref string cookieValue, ref string encodedSigKey)
        {
            //generate a random nonce
            string nonce = RandomHash.GetRandomHex(PUB_KEY_JWT_NONCE_SIZE);

            //Generate signing key
            using JsonWebToken jwt = new();
            //No header to write, we know the format

            //add the clients public key and set iat/exp 
            jwt.InitPayloadClaim()
                .AddClaim("sub", secInfo.ClientData)
                .AddClaim("iat", entity.RequestedTimeUtc.ToUnixTimeSeconds())
                .AddClaim("exp", entity.RequestedTimeUtc.Add(_config.AuthorizationValidFor).ToUnixTimeSeconds())
                .AddClaim("nonce", nonce)
                .AddClaim("aud", entity.Server.RequestUri.GetLeftPart(UriPartial.Authority))
                .AddClaim("pk", secInfo.PublicKey)
                .CommitClaims();

            //genreate random signing key to store in the user's session
            byte[] signingKey = RandomHash.GetRandomBytes(_config.PubKeySigningKeySize);

            //Sign jwt
            jwt.Sign(signingKey, ClientTokenHmacType);

            //base32 encode the signing key 
            encodedSigKey = VnEncoding.ToBase32String(signingKey, false);

            //Compile the jwt for the cookie value
            cookieValue = jwt.Compile();

            //Zero signing key now were done using it
            MemoryUtil.InitializeBlock(signingKey);
        }

        private bool TryGetSavedAuthData(HttpEntity entity, ref ClientAuthData authData)
        {
            //Check session is valid for use
            if (!IsSessionValid(in entity.Session))
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
            string? base32Sig = GetSigningKey(in entity.Session);

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

                MemoryUtil.InitializeBlock(signingKey);

                using JsonDocument payload = jwt.GetPayload();

                /*
                 * If the signature is valid we should be able to safely recover the 
                 * propertes we need. We should be able to assume all servers in the 
                 * network assign the same properties to the jwt
                 */

                string aud = payload.RootElement.GetProperty("aud").GetString()!;
                long exp = payload.RootElement.GetProperty("exp").GetInt64();

                //Check the audience matches the authority of the connection
                if (!string.Equals(aud, entity.Server.RequestUri.GetLeftPart(UriPartial.Authority), StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                //Check the expiration time
                if (exp < entity.RequestedTimeUtc.ToUnixTimeSeconds())
                {
                    return false;
                }

                authData = new()
                {
                    ClientData = payload.RootElement.GetProperty("sub").GetString()!,
                    PublicKey = payload.RootElement.GetProperty("pk").GetString()!
                };

                return true;
            }
            catch (FormatException)
            {
                //JWT is invalid and could not be parsed
                _logger.Debug("Client public key JWT or message body was not valid from {ip}", entity.TrustedRemoteIp);
            }

            return false;
        }

        private bool VerifyConnectionOTPInternal(HttpEntity entity)
        {
            Debug.Assert(IsSessionValid(in entity.Session), "Session was assumed to be valid for this call");

            //Get the token from the client header, the client should always sent this
            string? signedMessage = GetOTPHeaderValue(entity);
          
            if (string.IsNullOrWhiteSpace(signedMessage))
            {
                return false;
            }

            //Get the stored shared symetric key
            string? sharedKey = GetLoginToken(in entity.Session);
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

                        if (string.IsNullOrWhiteSpace(unsafeUserOrigin))
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

        #region helperFunctions

        /// <summary>
        /// A non-secure check to determine if the connection has been elevated
        /// </summary>
        /// <param name="session">The session to check the status of</param>
        /// <returns>True of the session might be elevated</returns>
        public static bool IsSessionElevated(ref readonly SessionInfo session) 
            => string.IsNullOrWhiteSpace(GetLoginToken(in session)) == false;

        private void SetPubkeyCookie(HttpEntity entity, string value) 
            => _pubkeyCookie.SetCookie(entity, value);
        private string? GetOTPHeaderValue(HttpEntity entity) 
            => entity.Server.Headers[_config.TokenHeaderName];

        private static void SetSigningKey(ref readonly SessionInfo session, string? value) 
            => session[PUBLIC_KEY_SIG_KEY_ENTRY] = value!;
        private static void SetLoginToken(ref readonly SessionInfo session, string? value) 
            => session[LOGIN_TOKEN_ENTRY] = value!;

        private static string? GetSigningKey(ref readonly SessionInfo session) 
            => session[PUBLIC_KEY_SIG_KEY_ENTRY];
        private static string? GetLoginToken(ref readonly SessionInfo session) 
            => session[LOGIN_TOKEN_ENTRY];

        private static bool IsSessionValid(ref readonly SessionInfo session) 
            => session.IsSet && !session.IsNew && session.SessionType == SessionType.Web;

        #endregion
    }
}
