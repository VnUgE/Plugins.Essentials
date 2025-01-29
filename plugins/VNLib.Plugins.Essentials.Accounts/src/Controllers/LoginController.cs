/*
* Copyright (c) 2025 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: LoginEndpoint.cs 
*
* LoginEndpoint.cs is part of VNLib.Plugins.Essentials.Accounts which is part of the larger 
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

using System;
using System.Net;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using System.Collections.Generic;
using System.Collections.Frozen;

using FluentValidation;

using VNLib.Utils;
using VNLib.Utils.Logging;
using VNLib.Plugins.Essentials.Users;
using VNLib.Plugins.Extensions.Validation;
using VNLib.Plugins.Essentials.Accounts.MFA;
using VNLib.Plugins.Essentials.Accounts.Validators;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Users;
using static VNLib.Plugins.Essentials.Statics;
using VNLib.Plugins.Essentials.Accounts.AccountRpc;
using VNLib.Plugins.Extensions.Loading.Configuration;

namespace VNLib.Plugins.Essentials.Accounts.Controllers
{

    [ConfigurationName("login")]
    internal sealed class LoginController(PluginBase plugin, IConfigScope config) : IAccountRpcController
    {
        public const string INVALID_MESSAGE = "Please check your email or password. You may get locked out.";
        public const string LOCKED_ACCOUNT_MESSAGE = "You have been timed out, please try again later";
        public const string MFA_ERROR_MESSAGE = "Invalid or expired request.";

        private readonly MfaAuthManager mfa = plugin.GetOrCreateSingleton<MfaAuthManager>();
        private readonly UserManager users = plugin.GetOrCreateSingleton<UserManager>();
        private readonly LoginConfigJson conf = config.DeserialzeAndValidate<LoginConfigJson>();

        /// <inheritdoc/>
        public IAccountRpcMethod[] GetMethods()
        {
            //only include mfa methods if mfa is enabled
            if (mfa.Armed)
            {
                return [
                    new LogoutMethod(),
                    new UserPassLoginMethod(plugin, conf, mfa, users),

                    //Enable mfa methods
                    new MfaGetDataMethod(mfa, users),
                    new MfaLoginMethod(plugin, conf, mfa, users),
                    new MfaRpcMethod(mfa, users)
               ];
            }
            else
            {
                return [
                    new LogoutMethod(),
                    new UserPassLoginMethod(plugin, conf, mfa, users)
               ];
            }
        }


        private sealed class LogoutMethod : IAccountRpcMethod
        {
            ///<inheritdoc/>
            public string MethodName => "logout";

            ///<inheritdoc/>
            public RpcMethodOptions Flags => RpcMethodOptions.None;

            ///<inheritdoc/>
            public ValueTask<object?> OnUserGetAsync(HttpEntity entity) => default;

            ///<inheritdoc/>
            public ValueTask<RpcCommandResult> InvokeAsync(HttpEntity entity, AccountJRpcRequest _, JsonElement args)
            {
                /*
                * If a connection is not properly authorized to modify the session
                * we can invalidate the client by detaching the session. This 
                * should cause the session to remain in tact but the client will
                * be detached.
                * 
                * This prevents attacks where connection with just a stolen session 
                * id can cause the client's session to be invalidated. 
                */

                if (entity.IsClientAuthorized(AuthorzationCheckLevel.Critical))
                {
                    entity.InvalidateLogin();
                }
                else
                {
                    //Detatch the session to cause client only invalidation
                    entity.Session.Detach();
                }

                return ValueTask.FromResult(RpcCommandResult.Okay());
            }
        }

        /*
         * Password only log-ins should be immune to repeat attacks on the same backend, because sessions are 
         * guarunteed to be mutally exclusive on the same system, therefor a successful login cannot be repeated
         * without a logout with the proper authorization.
         * 
         * Since MFA upgrades are indempodent upgrades can be regenerated continually as long as the session 
         * is not authorized, however login authorizations should be immune to repeats because session locking
         * 
         * Session id's are also regenerated per request, the only possible vector could be stale session cache
         * that has a valid MFA key and an old, but valid session id.
         */

        private sealed class UserPassLoginMethod(
            PluginBase pbase,
            LoginConfigJson config,
            MfaAuthManager MultiFactor,
            UserManager Users
        ) : IAccountRpcMethod
        {
            private readonly ILogProvider Log = pbase.Log.CreateScope("LOGIN");
            private readonly LoginMessageValidation LmValidator = new(config.EnforceEmailAddress, config.UsernameMaxChars);
            private readonly FailedLoginLockout Lockout = new(config.MaxLoginAttempts, TimeSpan.FromSeconds(config.FailedAttemptTimeoutSec));

            ///<inheritdoc/>
            public string MethodName => "login";

            ///<inheritdoc/>
            public RpcMethodOptions Flags => RpcMethodOptions.None;

            ///<inheritdoc/>
            public ValueTask<object?> OnUserGetAsync(HttpEntity entity)
            {
                return new ValueTask<object?>(new
                {
                    type                = "login",
                    enforce_email       = config.EnforceEmailAddress,
                    username_max_chars  = config.UsernameMaxChars
                });
            }

            ///<inheritdoc/>
            public async ValueTask<RpcCommandResult> InvokeAsync(HttpEntity entity, AccountJRpcRequest _, JsonElement args)
            {
                WebMessage webm = new();

                //Conflict if user is logged in
                if (entity.IsClientAuthorized(AuthorzationCheckLevel.Any))
                {
                    webm.Result = "You are already logged-in, please clear your cookies";
                    return RpcCommandResult.Error(HttpStatusCode.Conflict, webm);
                }

                if (args.ValueKind != JsonValueKind.Object)
                {
                    webm.Result = "Method arugments malformatted";
                    return RpcCommandResult.Error(HttpStatusCode.Conflict, webm);
                }

                try
                {
                    //Make sure the id is regenerated (or upgraded if successful login)
                    entity.Session.RegenID();

                    //Deserialize a login message from the request
                    using LoginMessage? loginMessage = args.Deserialize<LoginMessage>(SR_OPTIONS);

                    if (webm.Assert(loginMessage != null, "Invalid request data"))
                    {
                        return RpcCommandResult.Error(HttpStatusCode.BadRequest, webm);
                    }

                    //validate the message
                    if (!LmValidator.Validate(loginMessage, webm))
                    {
                        return RpcCommandResult.Error(HttpStatusCode.UnprocessableContent, webm);
                    }

                    using IUser? user = await Users.GetUserFromUsernameAsync(
                        loginMessage.UserName,
                        entity.EventCancellation
                    );

                    //Make sure account exists
                    if (webm.Assert(user != null, INVALID_MESSAGE))
                    {
                        return RpcCommandResult.Okay(webm);
                    }

                    bool locked = Lockout.CheckOrClear(user, entity.RequestedTimeUtc);

                    //Make sure the account has not been locked out
                    if (webm.Assert(!locked, LOCKED_ACCOUNT_MESSAGE))
                    {
                        //No need to re-increment the count
                        goto Cleanup;
                    }

                    //Only allow local accounts
                    if (!user.IsLocalAccount())
                    {
                        goto Failed;
                    }

                    //Only allow active users
                    if (!IsUserActive(user))
                    {
                        //This is an unhandled case, and should never happen, but just incase write a warning to the log
                        Log.Warn(
                            "Account {uid} has invalid status value and a login was attempted from {ip}",
                            user.UserID[..8],
                            entity.TrustedRemoteIp
                        );

                        goto Failed;
                    }

                    //Validate password
                    if (!await ValidatePasswordAsync(user, loginMessage, entity.EventCancellation))
                    {
                        goto Failed;
                    }

                    // ! PASSWORD ACCEPTED !

                    //Reset flc for account, either the user will be authorized, or the mfa will be triggered, but the flc should be reset
                    user.ClearFailedLoginCount();

                    //Force MFA If enabled
                    if (MultiFactor.RequiredForUser(user))
                    {
                        //Return the upgrade message to the user
                        webm.Result = GetMfaUpgrade(entity, loginMessage, user);
                        webm.Success = true;

                        Log.Verbose("MFA upgrade enforced for user {uid}...", user.UserID[..8]);

                        goto Cleanup;
                    }
                    else
                    {
                        /*
                         * ###################################################
                         * 
                         *               AUTHORIZATION ZONE
                         *               
                         *       Connection will be elevated to authorized
                         *       this is a successful login!
                         * 
                         * ####################################################
                         */

                        //Elevate the login status of the session to reflect the user's status
                        entity.GenerateAuthorization(loginMessage, user, webm);

                        webm.Result = new AccountData() { EmailAddress = user.EmailAddress };
                        webm.Success = true;

                        Log.Verbose("Successful login for user {uid}...", user.UserID[..8]);

                        goto Cleanup;
                    }

                Failed:

                    //Inc failed login count
                    Lockout.Increment(user, entity.RequestedTimeUtc);
                    webm.Result = INVALID_MESSAGE;

                Cleanup:
                    await user.ReleaseAsync();
                }
                catch (UserUpdateException uue)
                {
                    Log.Warn(uue);
                    return RpcCommandResult.Error(HttpStatusCode.ServiceUnavailable);
                }
                /*
                  * Account auhorization may throw excetpions if the configuration does not 
                  * match the client, or the client sent invalid or malicous data and 
                  * it could not grant authorization
                  */
                catch (OutOfMemoryException)
                {
                    webm.Result = "Your browser sent malformatted security information";
                }
                catch (CryptographicException ce)
                {
                    webm.Result = "Your browser sent malformatted security information";
                    Log.Debug(ce);
                }

                return RpcCommandResult.Okay(webm);
            }

            private static bool IsUserActive(IUser user) => user.Status == UserStatus.Active;

            private async Task<bool> ValidatePasswordAsync(IUser user, LoginMessage login, CancellationToken cancellation)
            {
                //Validate password against store
                ERRNO valResult = await Users.ValidatePasswordAsync(
                    user,
                    password: login.Password!,
                    flags: PassValidateFlags.None,
                    cancellation
                );

                return valResult == UserPassValResult.Success;
            }

            private MfaUpgradeResponse GetMfaUpgrade(HttpEntity entity, LoginMessage loginMessage, IUser user)
            {
                return new()
                {
                    MultiFactorUpgrade = true,
                    Upgrade = MultiFactor.GetChallengeMessage(entity, user, loginMessage)
                };
            }

            private sealed class MfaUpgradeResponse
            {
                [JsonPropertyName("upgrade")]
                public required string Upgrade { get; set; }

                [JsonPropertyName("mfa")]
                public required bool MultiFactorUpgrade { get; set; }
            }
        }

        private sealed class MfaLoginMethod(
            PluginBase plugin,
            LoginConfigJson config,
            MfaAuthManager MultiFactor,
            UserManager Users
        ) : IAccountRpcMethod
        {
            private readonly ILogProvider _log = plugin.Log.CreateScope("MFA Login");
            private readonly FailedLoginLockout Lockout = new(
                config.MaxLoginAttempts,
                TimeSpan.FromSeconds(config.FailedAttemptTimeoutSec)
            );

            ///<inheritdoc/>
            public string MethodName => "mfa.login";

            ///<inheritdoc/>
            public RpcMethodOptions Flags => RpcMethodOptions.None;

            ///<inheritdoc/>
            public ValueTask<object?> OnUserGetAsync(HttpEntity entity) => default;

            ///<inheritdoc/>
            public async ValueTask<RpcCommandResult> InvokeAsync(HttpEntity entity, AccountJRpcRequest message, JsonElement args)
            {
                WebMessage webm = new();

                if (args.ValueKind != JsonValueKind.Object)
                {
                    webm.Result = "Invalid request data";
                    return RpcCommandResult.Error(HttpStatusCode.BadRequest, webm);
                }

                MfaChallenge? upgrade = MultiFactor.GetChallengeData(entity, args);

                /*
                 * Upgrade may be null if it is not valid, not correctly formatted,
                 * expired, and so on. We cannot leak information about the upgrade
                 * request to the client, so return a generic error message
                 */
                if (webm.Assert(upgrade != null, MFA_ERROR_MESSAGE))
                {
                    return RpcCommandResult.Okay(webm);
                }

                using IUser? user = await Users.GetUserFromUsernameAsync(upgrade.UserName!);

                if (webm.Assert(user != null, MFA_ERROR_MESSAGE))
                {
                    return RpcCommandResult.Okay(webm);
                }

                bool locked = Lockout.CheckOrClear(user, entity.RequestedTimeUtc);

                if (webm.Assert(!locked, LOCKED_ACCOUNT_MESSAGE))
                {
                    //Locked, so clear stored signature
                    MultiFactor.InvalidateUpgrade(entity);
                }
                else if (MultiFactor.VerifyResponse(upgrade, user, args))
                {
                    /*
                     * ###################################################
                     * 
                     *               AUTHORIZATION ZONE
                     *               
                     *       Connection will be elevated to authorized
                     *       this is a successful login!
                     * 
                     * ####################################################
                     */

                    MultiFactor.InvalidateUpgrade(entity);

                    /*
                     * Time to authorize the user now. This will cause state changs
                     * to the client session, and user account. The user
                     * is now authorized to use the session.
                     */
                    entity.GenerateAuthorization(upgrade, user, webm);

                    webm.Result = new AccountData()
                    {
                        EmailAddress = user.EmailAddress,
                    };

                    webm.Success = true;

                    _log.Verbose("Successful login for user {uid}...", user.UserID[..8]);
                }
                else
                {
                    webm.Result = "Please check your input and try again.";
                }

                //Flush any changes to the user store
                await user.ReleaseAsync();

                return RpcCommandResult.Okay(webm);
            }
        }

        private sealed class MfaGetDataMethod(MfaAuthManager MultiFactor, UserManager Users) : IAccountRpcMethod
        {

            ///<inheritdoc/>
            public string MethodName => "mfa.get";

            ///<inheritdoc/>
            public RpcMethodOptions Flags => RpcMethodOptions.AuthRequired;

            ///<inheritdoc/>
            public ValueTask<object?> OnUserGetAsync(HttpEntity entity) => default;

            ///<inheritdoc/>
            public async ValueTask<RpcCommandResult> InvokeAsync(HttpEntity entity, AccountJRpcRequest message, JsonElement args)
            {
                using IUser? user = await Users.GetUserFromIDAsync(
                    userId: entity.Session.UserID,
                    entity.EventCancellation
                );

                if (user is null)
                {
                    return RpcCommandResult.Error(HttpStatusCode.NotFound);
                }

                MfaFunctionality funcs = new()
                {
                    SupportedMethods = MultiFactor.SupportedMethods
                };

                //Get results for each method
                foreach (IMfaProcessor method in MultiFactor.Processors)
                {
                    //Only add method to the list if it's enabled for the user
                    if (method.MethodEnabledForUser(user))
                    {
                        object? data = await method.OnUserGetAsync(entity, user);

                        funcs.Methods.Add(new MfaMethodResponse
                        {
                            Enabled = true,
                            Type    = method.Type,
                            Data    = data
                        });
                    }
                }

                return RpcCommandResult.Okay(response: funcs);
            }

            private sealed class MfaFunctionality
            {
                /// <summary>
                /// The MFA methods that are supported by the server
                /// </summary>
                [JsonPropertyName("supported_methods")]
                public string[] SupportedMethods { get; set; } = [];

                [JsonPropertyName("methods")]
                public List<MfaMethodResponse> Methods { get; set; } = [];
            }

            private sealed class MfaMethodResponse
            {
                [JsonPropertyName("type")]
                public required string Type { get; set; }

                [JsonPropertyName("enabled")]
                public required bool Enabled { get; set; }

                [JsonPropertyName("data")]
                public required object? Data { get; set; }

            }
        }


        private sealed class MfaRpcMethod(MfaAuthManager MultiFactor, UserManager Users) : IAccountRpcMethod
        {
            private readonly FrozenDictionary<string, IMfaProcessor> _processors = MultiFactor.Processors
                .ToFrozenDictionary(
                    static p => p.Type,
                    static p => p
                );

            ///<inheritdoc/>
            public string MethodName => "mfa.rpc";

            //All mfa rpc messages require auth to manipulate
            ///<inheritdoc/>
            public RpcMethodOptions Flags => RpcMethodOptions.AuthRequired;

            ///<inheritdoc/>
            public ValueTask<object?> OnUserGetAsync(HttpEntity entity) => default;

            ///<inheritdoc/>
            public async ValueTask<RpcCommandResult> InvokeAsync(HttpEntity entity, AccountJRpcRequest _, JsonElement args)
            {
                if (
                    args.ValueKind == JsonValueKind.Object
                    && args.TryGetProperty("type", out JsonElement typeEl)
                    && typeEl.ValueKind == JsonValueKind.String
                )
                {
                    string methodType = typeEl.GetString()!;

                    //Exec command against mfa processor if found
                    if (_processors.TryGetValue(methodType, out IMfaProcessor? proc))
                    {
                        //All mfa requests need a user object
                        using IUser? user = await Users.GetUserFromIDAsync(
                            userId: entity.Session.UserID,
                            entity.EventCancellation
                        );

                        if (user is not null)
                        {
                            object? response = await proc.OnHandleMessageAsync(entity, args, user);

                            return RpcCommandResult.Okay(response);
                        }
                    }
                }

                return RpcCommandResult.Error(HttpStatusCode.NotFound);
            }
        }

        private sealed class LoginConfigJson : IOnConfigValidation
        {

            [JsonPropertyName("max_login_attempts")]
            public uint MaxLoginAttempts { get; init; } = 5;

            [JsonPropertyName("failed_attempt_timeout_sec")]
            public int FailedAttemptTimeoutSec { get; init; } = 600;

            /// <summary>
            /// A value that indicates if the email address is required for 
            /// a username value
            /// </summary>
            [JsonPropertyName("enforce_email_address")]
            public bool EnforceEmailAddress { get; init; }

            [JsonPropertyName("username_max_chars")]
            public int UsernameMaxChars { get; init; } = 64;

            public void OnValidate()
            {
                Validate.Range(MaxLoginAttempts, 1u, 100u, "max_login_attempts");
                Validate.Range(FailedAttemptTimeoutSec, 60, 3600, "failed_attempt_timeout_sec");
                Validate.Range(UsernameMaxChars, 1, 128, "username_max_chars");
            }
        }
    }
}
