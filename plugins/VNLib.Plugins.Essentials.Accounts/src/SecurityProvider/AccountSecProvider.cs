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
using System.Threading.Tasks;

using VNLib.Net.Http;
using VNLib.Utils;
using VNLib.Utils.Logging;
using VNLib.Plugins.Essentials.Users;
using VNLib.Plugins.Essentials.Sessions;
using VNLib.Plugins.Essentials.Middleware;
using VNLib.Plugins.Essentials.Extensions;
using VNLib.Plugins.Extensions.Loading;

namespace VNLib.Plugins.Essentials.Accounts.SecurityProvider
{

    [ConfigurationName("account_security", Required = false)]
    [MiddlewareImpl(MiddlewareImplOptions.SecurityCritical)]
    internal sealed class AccountSecProvider : IAccountSecurityProvider, IHttpMiddleware
    {
        private readonly AccountSecConfig _config;
        private readonly SingleCookieController _statusCookie;
        private readonly ClientWebAuthManager _authManager;
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

            _logger = plugin.Log.CreateScope("Acnt-Sec");

            _authManager = new(config, _logger);
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
                else if (session.IsNew)
                {
                    //explicitly expire cookies on new sessions
                    ExpireCookies(entity, false);
                }
                //See if the session might be elevated
                else if (ClientWebAuthManager.IsSessionElevated(in session))
                {
                    //If the session stored a user-agent, make sure it matches the connection
                    if (_config.StrictUserAgent && !string.Equals(session.UserAgent, entity.Server.UserAgent, StringComparison.Ordinal))
                    {
                        _logger.Debug("Denied authorized connection from {ip} because user-agent changed", entity.TrustedRemoteIp);
                        return ValueTask.FromResult(FileProcessArgs.Deny);
                    }
                }
                else
                {
                    /*
                     * Attempts to clear client cookies if the session is not elevated
                     * and the client may still have cookies set from a previous session
                     * 
                     * Cookies are only sent if the client also sent login cookies to avoid 
                     * sending cookies on every request
                     */
                    ExpireCookies(entity, false);
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

                //Clear auth specifc cookies
                _authManager.DestroyAuthorization(entity);
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

            if (!IsSessionStateValid(in entity.Session))
            {
                throw new ArgumentException("The session is no configured for authorization");
            }

            ClientAuthData cad = ClientAuthData.FromSecInfo(clientInfo);

            string clientData = _authManager.AuthorizeConnection(entity, in cad);

            //set client status cookie via handler
            _statusCookie.SetCookie(entity, user.IsLocalAccount() ? "1" : "2");

            //Return the new authorzation
            return new EncryptedTokenAuthorization(clientData);
        }

        ///<inheritdoc/>
        IClientAuthorization IAccountSecurityProvider.ReAuthorizeClient(HttpEntity entity)
        {
            //Confirm session is configured
            if (!IsSessionStateValid(in entity.Session))
            {
                throw new InvalidOperationException("The session is not configured for authorization");
            }

            string clientData = string.Empty;

            //recover the client's public key
            if (!_authManager.TryReAuthorizeConnection(entity, ref clientData))
            {
                throw new InvalidOperationException("The user does not have the required public key token stored");
            }

            //re-set the client status cookie on successful re-auth
            _statusCookie.SetCookie(entity, entity.Session.HasLocalAccount() ? "1" : "2");

            return new EncryptedTokenAuthorization(clientData);
        }

        ///<inheritdoc/>
        void IAccountSecurityProvider.InvalidateLogin(HttpEntity entity)
        {
            //Client should also destroy the session
            ExpireCookies(entity, true);

            //Clear known security keys
            _authManager.DestroyAuthorization(entity);
        }

        ///<inheritdoc/>
        bool IAccountSecurityProvider.IsClientAuthorized(HttpEntity entity, AuthorzationCheckLevel level)
        {
            //Session must be loaded and not-new for an authorization to exist
            if(!IsSessionStateValid(in entity.Session))
            {
                return false;
            }

            return level switch
            {
                //Accept the client token or the cookie as any/medium 
                AuthorzationCheckLevel.Any or AuthorzationCheckLevel.Medium => _authManager.HasMinimalAuthorization(entity),
                //Critical requires that the client cookie is set and the token is set
                AuthorzationCheckLevel.Critical => _authManager.VerifyConnectionOTP(entity),
                //Default to false condition
                _ => false,
            };
        }

        ///<inheritdoc/>
        ERRNO IAccountSecurityProvider.TryEncryptClientData(HttpEntity entity, ReadOnlySpan<byte> data, Span<byte> outputBuffer)
        {
            string pubKey = string.Empty;

            //Recover the signed public key, already does session checks
            return _authManager.TryGetEncryptionPubkey(entity, ref pubKey) ? RsaClientDataEncryption.TryEncrypt(pubKey, data, outputBuffer) : ERRNO.E_FAIL;
        }

        ///<inheritdoc/>
        ERRNO IAccountSecurityProvider.TryEncryptClientData(IClientSecInfo entity, ReadOnlySpan<byte> data, Span<byte> outputBuffer)
        {
            //Use the public key supplied by the csecinfo 
            return RsaClientDataEncryption.TryEncrypt(entity.PublicKey, data, outputBuffer);
        }

        private static bool IsSessionStateValid(in SessionInfo session) => session.IsSet && !session.IsNew && session.SessionType == SessionType.Web;

        #endregion   

        private void ExpireCookies(HttpEntity entity, bool force)
        {
            _statusCookie.ExpireCookie(entity, force);
            _authManager.ExpireCookies(entity, force);
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
