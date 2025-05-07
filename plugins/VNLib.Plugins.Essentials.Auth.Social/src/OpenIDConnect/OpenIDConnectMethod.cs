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

using RestSharp;

using FluentValidation;
using FluentValidation.Results;

using VNLib.Hashing;
using VNLib.Utils.Memory;
using VNLib.Utils.Logging;
using VNLib.Utils.Extensions;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Validation;
using VNLib.Plugins.Essentials.Users;
using VNLib.Plugins.Essentials.Accounts;


namespace VNLib.Plugins.Essentials.Auth.Social.OpenIDConnect
{

    internal sealed class OpenIdConnectMethod : ISocialOauthController, IAsyncConfigurable
    {
        const string AuthErrorString = "An error occurred during authentication";

        private readonly OidcConfigJson Config;
        private readonly OpenIdConnectClient Client;
        private readonly ILogProvider Log;
        private readonly SocialOauthConfigJson ServiceConfig;
        private readonly IOidcIdenityAdapter IdentityAdapter;

        private bool Loaded;
        private string? Error;

        public OpenIdConnectMethod(PluginBase plugin, SocialOauthConfigJson serviceConfig, JsonElement config)
        {
            Config = config.Deserialize<OidcConfigJson>()!;           
            ServiceConfig = serviceConfig ?? throw new ArgumentNullException(nameof(serviceConfig));

            Log = plugin.Log.CreateScope($"OIDC-{Config.FriendlyName}");

            IOnDemandSecret clientSecret = plugin.Secrets()
                .GetOnDemandSecret(Config.SecretName!);

            Client = new OpenIdConnectClient(Config, clientSecret);
            Error = $"OIDC Method {Config.FriendlyName} is not available yet";

            //Currently just oidc, but eventually can be other types that can adapt to other types of OAuth providers
            IdentityAdapter = new GenericOidcIdentityAdapter(Config, Client);
        }

        public async Task ConfigureServiceAsync(PluginBase plugin)
        {
            //Run an OIDC discovery if the discovery url is set
            if (!string.IsNullOrWhiteSpace(Config.DiscoveryUrl))
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
                    OpenIdDiscoveryResult serverInfo = await Client.DiscoverSourceAsync(Config.DiscoveryUrl!, plugin.UnloadToken);

                    //Update the server info with the fetched data
                    Config.TokenEndpoint = serverInfo.TokenEndpoint ?? Config.TokenEndpoint;
                    Config.AuthorizationEndpoint = serverInfo.AuthorizationEndpoint ?? Config.AuthorizationEndpoint;
                    Config.UserInfoEndpoint = serverInfo.UserInfoEndpoint ?? Config.UserInfoEndpoint;
                    Config.JwksUri = serverInfo.JwksUri ?? Config.JwksUri;
                    Config.LogoutEndpoint = serverInfo.LogoutEndpoint ?? Config.LogoutEndpoint;

                    Error = null;
                    Loaded = true;

                    if (plugin.IsDebug())
                    {
                        Log.Debug("OIDC Discovery Document: {doc}", serverInfo);
                    }
                    else
                    {
                        Log.Verbose("OIDC Discovery Document fetched successfully");
                    }

                    if (!string.IsNullOrWhiteSpace(Config.LogoutEndpoint))
                    {
                        Log.Verbose("Logout endpoint has been configured");
                    }
                }
                catch (HttpRequestException ex)
                {
                    Log.Error("Failed to fetch OIDC discovery document: {error}", ex.Message);
                    Error = "Failed to fetch OIDC discovery document";
                    return;
                }
                catch (ValidationException ve)
                {
                    Log.Error(ve, "OIDC discovery document failed validation");
                    Error = $"OIDC discovery document failed validation. {ve.Message}";
                    return;
                }
                catch
                {
                    Error = "Failed to fetch OIDC discovery document for unkown reason";
                    throw;
                }
            }
            else
            {
                //If discovery is disabled, validate the config against required fields

                IValidator<OidcEndpointConfigJson> endpointVal = OidcEndpointConfigJson.GetValidator(userInfoRequired: true);
                ValidationResult res = endpointVal.Validate(Config);

                //If config is valid, then load the adapter and clear error
                if (res.IsValid)
                {
                    Error = null;
                    Loaded = true;

                    Log.Verbose("OIDC Endpoint is in manual mode and configured correctly. Loading identity provider");
                }
                else
                {
                    Log.Error("ODIC Endpoint is in manual mode but misconfigured: {errors}", res.Errors);
                    Error = "OIDC Endpoint is misconfigured";
                }
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
                bool sendErrors = manager.Config.SendErrorsToClient;

                return ValueTask.FromResult<object?>(new
                {
                    enabled         = manager.Loaded,
                    friendly_name   = manager.Config.FriendlyName,
                    icon_url        = manager.Config.IconUrl,
                    error           = sendErrors ? manager.Error : null,
                    logout_redirect = !string.IsNullOrWhiteSpace(manager.Config.LogoutEndpoint),
                });
            }

            /// <inheritdoc/>
            public ValueTask<SocialUpgradeResult> OnUpgradeAsync(SocialMethodState state, JsonElement args)
            {
                if (manager.Loaded)
                {
                    string nonce = GetStateTokenNonce();

                    return ValueTask.FromResult(new SocialUpgradeResult
                    {
                        Success     = true,
                        AuthUrl     = GetAuthUrl(nonce),
                        StateData   = new StateData { StateNonce = nonce }
                    });
                }
                else
                {
                    //Cannot upgrade if the server info is not loaded
                    return ValueTask.FromResult(new SocialUpgradeResult
                    {
                        Success     = false,
                        AuthUrl     = null,
                        StateData   = null
                    });
                }
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

                if (webm.AssertError(manager.Loaded, "Server info is not loaded"))
                {
                    return webm;
                }

                if (webm.AssertError(auth is not null, "Your authentication request is null"))
                {
                    return webm;
                }

                if (!_authReqValidator.Validate(auth, webm))
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

                try
                {
                    OpenIdTokenResponse token = await manager.Client.ExchangeCodeForTokenAsync(
                        manager.Config.TokenEndpoint,
                        accessCode: auth.Code,
                        state.Entity.EventCancellation
                    );

                    await AuthorizeClientFromPlatformId(state, secInfo, webm, token);

                    //Store access token info for future use
                    state.SetSecretData(new
                    {
                        access_token = token.Token,
                        refresh_token = token.RefreshToken,
                    });                 
                }
                catch (HttpRequestException hre)
                {
                    manager.Log.Error("Failed to exchange code for token due to an HTTP error: {error}", hre.Message);

                    webm.Result = null;
                    webm.AssertError(false, 
                    [
                        "Failed to authenticate with service",
                    ]);
                }

                return webm;
            }
         

            ///<inheritdoc/>
            public ValueTask<object?> OnLogoutAsync(SocialMethodState state, JsonElement args)
            {
                // Always invalidate the session, then continue the optional redirect
                state.Entity.InvalidateLogin();

                //See if the logout endpoint is set
                if (!string.IsNullOrWhiteSpace(manager.Config.LogoutEndpoint))
                {
                    return ValueTask.FromResult<object?>(new
                    {
                        //Return the client a logout url to redirect to
                        redirect_url = GetLogoutUrl()
                    });
                }

                return ValueTask.FromResult<object?>(null);
            }

            private async Task AuthorizeClientFromPlatformId(SocialMethodState state, IClientSecInfo secInfo, WebMessage webm, OpenIdTokenResponse token)
            {
                //Get the user info from the adapter so we can log the user in
                OidcLoginDataResult loginData = await manager.IdentityAdapter.GetLoginDataAsync(state, token);

                if (webm.AssertError(loginData.IsValid, loginData.Error!))
                {
                    return;
                }

                /*
                 * If the configuration requires using an email address as a username,
                 * vs the platform id, then we need to get the user from the email address
                 */
                IUser? user = manager.Config.UseEmailAsUsername
                    ? await state.Users.GetUserFromUsernameAsync(loginData.Username!, state.Entity.EventCancellation)
                    : await state.Users.GetUserFromIDAsync(loginData.Username!, state.Entity.EventCancellation);

                if (user is null)
                {
                    //User must be created if configuration allows it
                    if (manager.ServiceConfig.CanCreateUser)
                    {
                        //create a new user if the user does not exist
                        user = await CreateUserAsync(state, token, webm);

                        if(user is null)
                        {
                            return;
                        }
                    }
                    else
                    {
                        webm.Result = AuthErrorString;
                        return;
                    }
                }

                try
                {
                    if (webm.AssertError(user is not null, AuthErrorString))
                    {
                        manager.Log.Verbose("User was not found for id {platformId}", loginData.Username);
                        return;
                    }

                    if (webm.AssertError(user.Status == UserStatus.Active, AuthErrorString))
                    {
                        return;
                    }

                    //Social login may not be allowed for local accounts
                    bool allowLocal = manager.ServiceConfig.AllowForLocalAccounts;
                    if (webm.AssertError(allowLocal || !user.IsLocalAccount(), AuthErrorString))
                    {
                        return;
                    }

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
                    user?.Dispose();
                }
            }

            private async Task<IUser?> CreateUserAsync(SocialMethodState state, OpenIdTokenResponse token, WebMessage webm)
            {
                //Fetch the user data from the adapter for the current user auth token
                OidcNewUserDataResult userData = await manager.IdentityAdapter.GetNewUserDataAsync(state, token);

                if (webm.AssertError(userData.IsValid, userData.Error!))
                {
                    return null;
                }

                int passwordSize = manager.ServiceConfig.PasswordSize;

                UserCreationRequest req = new()
                {
                    Username        = userData.EmailAddress!,
                    Password        = PrivateString.ToPrivateString(RandomHash.GetRandomHex(passwordSize), ownsString: true),
                    InitialStatus   = UserStatus.Active,
                    Privileges      = manager.ServiceConfig.DefaultUserPrivilages,
                };

                try
                {
                    IUser? user = await state.Users.CreateUserAsync(
                        req,
                        userId: userData.SafeUserId!, //Userid is explicitly required so login works correctly for future logins
                        state.Users.GetHashProvider(),
                        state.Entity.EventCancellation
                    );

                    user.SetAccountOrigin(manager.Config.FriendlyName);

                    return user;
                }
                catch (UserCreationFailedException uce)
                {
                    manager.Log.Error("Failed to create user for {platformId} cause:\n{err}", userData.SafeUserId, uce);
                    webm.Result = AuthErrorString;
                }

                return null;
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

            private string GetStateTokenNonce()
            {
                return RandomHash.GetRandomBase32(manager.ServiceConfig.StateNonceSize);
            }

            private string GetAuthUrl(string nonce)
            {
                using UnsafeMemoryHandle<char> uriBuffer = MemoryUtil.UnsafeAlloc<char>(1024);

                ForwardOnlyWriter<char> writer = new(uriBuffer.Span);

                writer.AppendSmall(manager.Config!.AuthorizationEndpoint);
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

            private string GetLogoutUrl()
            {
                using UnsafeMemoryHandle<char> uriBuffer = MemoryUtil.UnsafeAlloc<char>(1024);

                ForwardOnlyWriter<char> writer = new(uriBuffer.Span);

                writer.AppendSmall(manager.Config.LogoutEndpoint);
                writer.AppendSmall("?client_id=");
                writer.AppendSmall(manager.Config.ClientId);
                writer.AppendSmall("&post_logout_redirect_uri=");
                writer.AppendSmall(manager.Config.RedirectUrl);              

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
        }
    }
}
