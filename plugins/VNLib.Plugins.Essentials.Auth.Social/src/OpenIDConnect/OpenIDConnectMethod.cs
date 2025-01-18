/*
* Copyright (c) 2025 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Auth.Social
* File: OpenIdConnectMethod.cs 
*
* OpenIdConnectMethod.cs is part of VNLib.Plugins.Essentials.Auth.Social which is part of the larger 
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
using System.Net.Http;
using System.Threading.Tasks;
using System.Text.Json;
using System.Security.Cryptography;
using System.Text.Json.Serialization;

using FluentValidation;

using VNLib.Hashing;
using VNLib.Hashing.IdentityUtility;
using VNLib.Utils.Memory;
using VNLib.Utils.Logging;
using VNLib.Utils.Extensions;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Validation;
using VNLib.Plugins.Essentials.Users;
using VNLib.Plugins.Essentials.Accounts;
using VNLib.Plugins.Essentials.Auth.Social.Controllers;


namespace VNLib.Plugins.Essentials.Auth.Social.OpenIDConnect
{
  
    internal sealed class OpenIdConnectMethod : ISocialOauthController, IAsyncConfigurable
    {
        const string AuthErrorString = "An error occurred during authentication";

        private readonly OidcConfigJson Config;
        private readonly OpenIdConnectClient Client;
        private readonly ILogProvider Log;

        private OpenIdDiscoveryResult? ServerInfo;
        private string? _error;

        public OpenIdConnectMethod(PluginBase plugin, JsonElement config)
        {
            Config = config.Deserialize<OidcConfigJson>()!;

            Log = plugin.Log.CreateScope($"OIDC Method {Config.FriendlyName}");

            IOnDemandSecret clientSecret = plugin.Secrets()
                .GetOnDemandSecret(Config.SecretName!);

            Client = new OpenIdConnectClient(Config, clientSecret);
            _error = $"OIDC Method {Config.FriendlyName} is not available yet";
        }

        public async Task ConfigureServiceAsync(PluginBase plugin)
        {
            Uri discoveryUri = new(Config.DiscoveryUrl!);

            /*
             * Resolve the IP addressess of the discovery server and print them to the screen so 
             * the sysadmin can verify the server's identity
             */
            IPAddress[] addresses = await Dns.GetHostAddressesAsync(discoveryUri.DnsSafeHost, plugin.UnloadToken);
            Log.Verbose("Discovery server {host} resolves to {ip}", discoveryUri.DnsSafeHost, addresses);

            try
            {
                //Fetch the discovery document
                ServerInfo = await Client.DiscoverSourceAsync(Config.DiscoveryUrl!, plugin.UnloadToken);
                _error = null;

                if (plugin.IsDebug())
                {
                    Log.Debug("OIDC Discovery Document: {doc}", ServerInfo);
                }
                else
                {
                    Log.Verbose("OIDC Discovery Document fetched successfully");
                }
            }
            catch (HttpRequestException ex)
            {
                Log.Error("Failed to fetch OIDC discovery document: {error}", ex.Message);
                _error = "Failed to fetch OIDC discovery document";
                return;
            }
            catch (ValidationException ve)
            {
                Log.Error(ve, "OIDC discovery document failed validation");
                _error = $"OIDC discovery document failed validation. {ve.Message}";
                return;
            }
            catch
            {
                _error = "Failed to fetch OIDC discovery document for unkown reason";
                throw;
            }
        }

        /// <inheritdoc/>
        public ISocialOauthMethod[] GetMethods()
        {
            return [new OidcOauthMethod(this)];
        }

        private sealed class OidcOauthMethod(OpenIdConnectMethod manager) : ISocialOauthMethod
        {
            private readonly AuthRequestValidator _authReqValidator = new();
            private readonly IdTokenValidator _idTokenValidator = new(manager);

            /*
             * The method id must be unique and not contain special characters like 
             * a friendly name might, but in order to have a cluster of backend servers
             * the name must shared between all servers. So hashing the friendly name
             * is a good way to ensure uniqueness and consistency
             */

            /// <inheritdoc/>
            public string MethodName { get; } = ManagedHash.ComputeHash(manager.Config.FriendlyName, HashAlg.SHA1, HashEncodingMode.Hexadecimal);

            /// <inheritdoc/>
            public ValueTask<object?> OnGetInfo(HttpEntity entity)
            {
                //If the server info has not been loaded or failed to load, the method is unavailable
                bool enabled = manager.ServerInfo is not null;
                bool sendErrors = manager.Config.SendErrorsToClient;

                return ValueTask.FromResult<object?>(new OnGetResult
                {
                    Enabled = enabled,
                    Name    = manager.Config.FriendlyName,
                    IconUrl = manager.Config.IconUrl,
                    Error   = sendErrors ? manager._error : null
                });
            }

            /// <inheritdoc/>
            public ValueTask<SocialUpgradeResult> OnUpgradeAsync(SocialMethodState state, JsonElement args)
            {
                //Cannot upgrade if the server info is not loaded
                if (manager.ServerInfo is null)
                {
                    return ValueTask.FromResult(new SocialUpgradeResult
                    {
                        Success     = false,
                        AuthUrl     = null,
                        StateData   = null
                    });
                }

                string nonce = GetStateTokenNonce();

                return ValueTask.FromResult(new SocialUpgradeResult
                {
                    Success     = true,
                    AuthUrl     = GetAuthUrl(nonce),
                    StateData   = new StateData { StateNonce = nonce }
                });
            }

            ///<inheritdoc/>
            public async ValueTask<object?> OnAuthenticateAsync(
                SocialMethodState state, 
                IClientSecInfo secInfo, 
                JsonElement requestArgs, 
                JsonElement stateDataJson
            )
            {
                WebMessage webm = new();

                StateData stateData = stateDataJson.Deserialize<StateData>()!;
                AuthenticateRequestJson? auth = requestArgs.Deserialize<AuthenticateRequestJson>();

                if(webm.AssertError(manager.ServerInfo is not null, "Server info is not loaded"))
                {
                    return webm;
                }

                if (webm.AssertError(auth is not null, "Your authentication request is null"))
                {
                    return webm;
                }

                if(!_authReqValidator.Validate(auth, webm))
                {
                    return webm;
                }

                if (webm.AssertError(ValidateReferIfExists(state, auth), "Invalid refer header please try again"))
                {
                    return webm;
                }

                //Ensure the state nonce matches the one we generated
                if (webm.AssertError(string.Equals(stateData.StateNonce, auth.State, StringComparison.OrdinalIgnoreCase), "State nonce mismatch"))
                {
                    return webm;
                }

                OpenIdTokenResponse token = await manager.Client.ExchangeCodeForTokenAsync(
                    manager.ServerInfo.TokenEndpoint!,
                    auth.Code,
                    state.Entity.EventCancellation
                );

                //If the connection sent an identity toke, we can use that to auth the user
                if (!string.IsNullOrWhiteSpace(token.IdToken))
                {
                    manager.Log.Verbose("Attempting to authorize session {user} in with identity token\n{token}", secInfo.ClientId, token.IdToken);

                    await AuthFromIdentityJwtAsync(state, secInfo, token.IdToken, webm);

                    if (webm.Success)
                    {
                        //Store oauth token for future use
                        state.SetSecretData(token.Token);
                    }
                }
                else
                {
                    //Otherwise we need to hit the user data endpoint

                    webm.Result = token;
                    webm.Success = true;
                }

                return webm;
            }

            private static bool ValidateReferIfExists(SocialMethodState state, AuthenticateRequestJson request)
            {
                if (state.Entity.Server.Referer is null)
                {
                    return true;
                }

                string query = state.Entity.Server.Referer.Query;

                //If the query contains the code and state parameters, make sure they match the request
                if (query.Contains("code="))
                {
                    /*
                        If the code paremter is set, the code should also exist in the query string
                        Yes this is a lazy way to avoid parsing, if the code is there it doesnt matter
                        if a hijaker changed the key name
                    */
                    if (!query.Contains(request.Code, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }
                }

                return !query.Contains("state=") || query.Contains(request.State, StringComparison.OrdinalIgnoreCase);
            }

            private Task AuthFromIdentityJwtAsync(SocialMethodState state, IClientSecInfo secInfo, string idTokenString, WebMessage webm)
            {
                using JsonWebToken idToken = JsonWebToken.Parse(idTokenString);
                OpenIdIdentityTokenJson? tokenData = idToken.GetPayload<OpenIdIdentityTokenJson>();

                if (webm.AssertError(tokenData is not null, AuthErrorString))
                {
                    return Task.CompletedTask;
                }

                //Validate the id token
                if(_idTokenValidator.Validate(tokenData, webm))
                {
                    return Task.CompletedTask;
                }

                bool isExpired = tokenData.Expiration < state.Entity.RequestedTimeUtc.ToUnixTimeSeconds();
                if (webm.AssertError(!isExpired, AuthErrorString))
                {
                    return Task.CompletedTask;
                }

                return AuthorizeUserFromEmail(state, secInfo, webm, tokenData.Email!);
            }

            private async Task AuthorizeUserFromEmail(SocialMethodState state, IClientSecInfo secInfo, WebMessage webm, string emailAddress)
            {
                using IUser? user = await state.Users.GetUserFromUsernameAsync(emailAddress, state.Entity.EventCancellation);

                if (webm.AssertError(user is not null, AuthErrorString))
                {
                    return;
                }

                if (webm.AssertError(user.Status == UserStatus.Active, AuthErrorString))
                {
                    return;
                }

                //Social login is not allowed for local accounts
                if (webm.AssertError(!user.IsLocalAccount(), AuthErrorString))
                {
                    return;
                }

                try
                {
                    //Generate authoization
                    state.Entity.GenerateAuthorization(secInfo, user, webm);
                   
                    webm.Success = true;
                    webm.Result = new
                    {
                        user.EmailAddress,
                        user.Created
                    };
                    
                    manager.Log.Debug("Successfull social login for user {uid}... from {ip}", user.UserID[..8], state.Entity.TrustedRemoteIp);

                    //release the user to push changes to the db
                    await user.ReleaseAsync();
                }
                catch (CryptographicException ce)
                {
                    manager.Log.Debug("Failed to generate authorization for {user}, error {err}", user.UserID, ce.Message);
                    webm.Result = AuthErrorString;
                }
                catch (OutOfMemoryException)
                {
                    manager.Log.Debug("Out of buffer space for token data encryption, for user {usr}, from ip {ip}", user.UserID, state.Entity.TrustedRemoteIp);
                    webm.Result = AuthErrorString;
                }
                catch (UserUpdateException uue)
                {
                    webm.Token = null;
                    webm.AssertError(false, AuthErrorString);

                    //destroy any login data on failure
                    state.Entity.InvalidateLogin();

                    manager.Log.Error("Failed to update the user's account cause:\n{err}", uue);
                }
                finally
                {
                    user.Dispose();
                }
            }


            public ValueTask<object?> OnLogoutAsync(SocialMethodState state, JsonElement request)
            {
                throw new NotImplementedException();
            }

            private string GetStateTokenNonce()
            {
                return RandomHash.GetRandomBase32(manager.Config.StateNonceSize);
            }

            private string GetAuthUrl(string nonce)
            {
                using UnsafeMemoryHandle<char> uriBuffer = MemoryUtil.UnsafeAlloc<char>(1024);

                ForwardOnlyWriter<char> writer = new(uriBuffer.Span);

                writer.AppendSmall(manager.ServerInfo!.AuthorizationEndpoint);
                writer.AppendSmall("?client_id=");
                writer.AppendSmall(manager.Config.ClientId);
                writer.AppendSmall("&redirect_uri=");
                writer.AppendSmall(manager.Config.RedirectUrl);
                writer.AppendSmall("&response_type=code&scope=");
                writer.AppendSmall(string.Join("%20", manager.Config.RequiredScopes));
                writer.AppendSmall("&state=");

                //Init unique state nonce for this endpoint
                writer.AppendSmall(nonce);

                return writer.ToString();
            }

            private sealed class StateData
            {
                [JsonPropertyName("nonce")]
                public required string? StateNonce { get; set; }
            }

            private sealed class OnGetResult
            {
                [JsonPropertyName("enabled")]
                public required bool Enabled { get; set; }

                [JsonPropertyName("friendly_name")]
                public required string Name { get; set; }

                [JsonPropertyName("icon_url")]
                public required string? IconUrl { get; set; }

                [JsonPropertyName("error")]
                public required string? Error { get; set; }
            }

            private sealed class AuthenticateRequestJson
            {
                [JsonPropertyName("code")]
                public required string Code { get; set; }

                [JsonPropertyName("state")]
                public required string State { get; set; }
            }

            private sealed class AuthRequestValidator: AbstractValidator<AuthenticateRequestJson>
            {
                public AuthRequestValidator()
                {
                    RuleFor(r => r.Code)
                        .NotEmpty()
                        //url safe characters
                        .Matches(@"^[a-zA-Z0-9\-._~:/#\[\]@!$'()+,;]{16,128}$");


                    RuleFor(r => r.State)
                        .NotEmpty()
                        .Matches(@"^[\w\d]{16,128}$");
                }
            }

            private sealed class IdTokenValidator: AbstractValidator<OpenIdIdentityTokenJson>
            {
                public IdTokenValidator(OpenIdConnectMethod config)
                {
                    //Audience tokem must match the client id
                    RuleFor(r => r.Audience)
                        .NotEmpty()
                        .Equal(config.Config.ClientId, StringComparer.OrdinalIgnoreCase);

                    RuleFor(r => r.Email)
                        .NotEmpty()
                        .EmailAddress();                        
                }
            }
        }
    }
}
