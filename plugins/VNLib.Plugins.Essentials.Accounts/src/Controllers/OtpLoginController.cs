/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: OtpLoginController.cs 
*
* OtpLoginController.cs is part of VNLib.Plugins.Essentials.Accounts which 
* is part of the larger VNLib collection of libraries and utilities.
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
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using System.Diagnostics.CodeAnalysis;

using FluentValidation;

using VNLib.Net.Http;
using VNLib.Utils.Logging;
using VNLib.Hashing.IdentityUtility;
using VNLib.Plugins.Essentials.Users;
using VNLib.Plugins.Extensions.Validation;
using VNLib.Plugins.Essentials.Accounts.Validators;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Users;
using VNLib.Plugins.Essentials.Accounts.MFA.Otp;
using VNLib.Plugins.Essentials.Accounts.AccountRpc;


namespace VNLib.Plugins.Essentials.Accounts.Controllers
{
    [ConfigurationName("otp_auth")]
    internal sealed class OtpLoginController(PluginBase plugin, IConfigScope config) : IAccountRpcController
    {
        public const string INVALID_MESSAGE = "Your assertion is invalid, please regenerate and try again";

        private static readonly JwtLoginValidator LwValidator = new();
        private static readonly IValidator<AuthenticationInfo> AuthValidator = AuthenticationInfo.GetValidator();

        ///<inheritdoc/>
        public IAccountRpcMethod[] GetMethods()
        {
            return [
                new OtpAuthMethod(plugin, config.DeserialzeAndValidate<PkOtpEndpointConfig>())
            ];
        }

        private sealed class OtpAuthMethod(PluginBase plugin, PkOtpEndpointConfig Config) : IAccountRpcMethod
        {
            private readonly UserManager _users = plugin.GetOrCreateSingleton<UserManager>();
            private readonly ILogProvider _log = plugin.Log.CreateScope("OTP");

            private readonly FailedLoginLockout _lockout = new(
                maxCounts: (uint)Config.MaxFailedLogins,
                maxTimeout: TimeSpan.FromSeconds(Config.FailedCountTimeoutSec)
            );

            public string MethodName => "otp.login";

            ///<inheritdoc/>
            public RpcMethodOptions Flags => RpcMethodOptions.None;

            ///<inheritdoc/>
            public ValueTask<object?> OnUserGetAsync(HttpEntity entity) => default;

            ///<inheritdoc/>
            public async ValueTask<RpcCommandResult> InvokeAsync(HttpEntity entity, AccountJRpcRequest message, JsonElement args)
            {
                //Conflict if user is logged in
                if (entity.IsClientAuthorized(AuthorzationCheckLevel.Any))
                {
                    return RpcCommandResult.Error(HttpStatusCode.Conflict);
                }

                if(args.ValueKind != JsonValueKind.Object)
                {
                    return RpcCommandResult.Error(HttpStatusCode.BadRequest);
                }

                ValErrWebMessage webm = new()
                {
                    Result = INVALID_MESSAGE,
                };

                //Get the login message from the client
                JwtLoginMessage? login = args.Deserialize<JwtLoginMessage>();

                if (login is null)
                {
                    goto Exit;
                }

                //Validate login message
                if (!LwValidator.Validate(login, webm))
                {
                    goto Exit;
                }

                IUser? user = null;
                JsonWebToken jwt;
                try
                {
                    //We can try to recover the jwt data, if the data is invalid, 
                    jwt = JsonWebToken.Parse(login.LoginJwt);
                }
                catch (KeyNotFoundException)
                {
                    goto Exit;
                }
                catch (FormatException)
                {
                    goto Exit;
                }

                try
                {

                    //Get auth info from jwt
                    bool isValidAuth = GetAuthInfo(jwt, entity.RequestedTimeUtc, out AuthenticationInfo? authInfo);

                    if (!isValidAuth || authInfo is null)
                    {
                        goto Exit;
                    }

                    //Validate auth info
                    if (!AuthValidator.Validate(authInfo, webm))
                    {
                        goto Exit;
                    }

                    /*
                     * If a pubic key was signed by the client, assign the signed key to the 
                     * login key field for further authorization
                     */
                    if (!string.IsNullOrWhiteSpace(authInfo.SignedPubkey))
                    {
                        login.PublicKey = authInfo.SignedPubkey;
                    }


                    //Get the user from the email address
                    user = await _users.GetUserFromUsernameAsync(
                        username: authInfo.EmailAddress!,
                        entity.EventCancellation
                    );

                    if (user is null)
                    {
                        goto Exit;
                    }

                    //Check failed login count
                    if (_lockout.CheckOrClear(user, entity.RequestedTimeUtc))
                    {
                        goto Exit;
                    }

                    //Now we can verify the signed message against the stored key
                    if (!IsOtpVerified(user, jwt, authInfo.KeyId!))
                    {
                        //increment flc on invalid signature
                        _lockout.Increment(user, entity.RequestedTimeUtc);

                        //Write change to database
                        await user.ReleaseAsync();

                        goto Exit;
                    }

                    if (!IsStatusValid(user))
                    {
                        goto Exit;
                    }

                    if (!IsOriginValid(entity.Server, authInfo))
                    {
                        goto Exit;
                    }

                    /*
                     ***********************************************
                     *
                     *             ! AUTH ZONE !
                     *              
                     *  The token has been verified and the session
                     *  will be upgraded
                     *
                     ***********************************************
                     */

                    //Authorize the session for the desired user
                    entity.GenerateAuthorization(login, user, webm);

                    //Write user data back to db
                    await user.ReleaseAsync();

                    webm.Success = true;
                    webm.Result = "Succesfully logged in";

                    _log.Verbose("Successful login for user {uid}...", user.UserID[..8]);

                    //Logged in!

                }
                catch (JsonException jse)
                {
                    //Invalidate incase it was set before the exception was raised
                    entity.InvalidateLogin();

                    webm.Errors = new ValidationErrorMessage[1]
                    {
                        new()
                        {
                            ErrorMessage = jse.Message,
                            PropertyName = "login",
                        }
                    };

                    webm.Result = "Please verify your login token and try again.";

                    return RpcCommandResult.Error(HttpStatusCode.UnprocessableEntity, webm);
                }
                catch
                {
                    /*
                     * If an internal error occurs after the authorization has been 
                     * generated, we need to clear the login state that has been created. 
                     */
                    entity.InvalidateLogin();
                    throw;
                }
                finally
                {
                    user?.Dispose();
                    jwt.Dispose();
                }

            Exit:
                return RpcCommandResult.Okay(webm);
            }


            private bool IsOriginValid(IConnectionInfo server, AuthenticationInfo info)
            {
                //If strict origin check is enabled, we need to verify the site origin
                if (Config.StrictOriginCheck)
                {
                    return string.Equals(
                        info.SiteOrigin,
                        server.RequestUri.GetLeftPart(UriPartial.Authority),
                        StringComparison.OrdinalIgnoreCase
                    );
                }

                return true;
            }

            private static bool IsStatusValid(IUser user)
            {
                //User must be active and have a local account
                return user.Status == UserStatus.Active
                    && user.IsLocalAccount();
            }

            private static bool IsOtpVerified(IUser user, JsonWebToken jwt, string keyid)
                => user.OtpVerifyUserJWT(jwt, keyid);

            private bool GetAuthInfo(JsonWebToken jwt, DateTimeOffset now, [NotNullWhen(true)] out AuthenticationInfo? authInfo)
            {
                authInfo = null;

                //Get the signed payload message
                using JsonDocument payload = jwt.GetPayload();

                long unixSec = payload.RootElement.GetProperty("iat").GetInt64();

                DateTimeOffset clientIat = DateTimeOffset.FromUnixTimeSeconds(unixSec);

                if (clientIat.Add(Config.MaxJwtTimeDifference) < now)
                {
                    return false;
                }

                if (clientIat.Subtract(Config.MaxJwtTimeDifference) > now)
                {
                    return false;
                }

                //Recover the authenticator information
                authInfo = payload.Deserialize<AuthenticationInfo>();

                return authInfo != null;
            }
        }

        private sealed class JwtLoginValidator : ClientSecurityMessageValidator<JwtLoginMessage>
        {
            public JwtLoginValidator() : base()
            {
                //Basic jwt validator
                RuleFor(l => l.LoginJwt)
                    .MinimumLength(50)
                    //Token should not contain illegal chars, only base64url + '.'
                    .IllegalCharacters()
                    //Make sure the jwt contains exacly 2 '.' chracters
                    .Must(static l => l?.Count(static c => c == '.') == 2)
                    .WithMessage("Your credential is not a valid Json Web Token");
            }
        }

        private sealed class JwtLoginMessage : IClientSecInfo
        {
            [JsonPropertyName("pubkey")]
            public string? PublicKey { get; set; }

            [JsonPropertyName("clientid")]
            public string? ClientId { get; set; }

            [JsonPropertyName("login")]
            public string? LoginJwt { get; set; }
        }

        private sealed class PkOtpEndpointConfig : IOnConfigValidation
        {
            [JsonIgnore]
            public TimeSpan MaxJwtTimeDifference { get; set; } = TimeSpan.FromSeconds(30);

            [JsonPropertyName("jwt_time_dif_sec")]
            public uint TimeDiffSeconds
            {
                get => (uint)MaxJwtTimeDifference.TotalSeconds;
                set => TimeSpan.FromSeconds(value);
            }

            [JsonPropertyName("max_login_attempts")]
            public int MaxFailedLogins { get; set; } = 10;

            [JsonPropertyName("failed_attempt_timeout_sec")]
            public double FailedCountTimeoutSec { get; set; } = 300;

            [JsonPropertyName("strict_origin_check")]
            public bool StrictOriginCheck { get; set; } = false;

            public void OnValidate()
            {
                InlineValidator<PkOtpEndpointConfig> val = new();

                val.RuleFor(c => c.TimeDiffSeconds)
                    .GreaterThan((uint)1)
                    .WithMessage("You must specify a JWT IAT time difference greater than 0 seconds");

                val.RuleFor(c => c.MaxFailedLogins)
                    .GreaterThan(0);

                val.RuleFor(c => c.FailedCountTimeoutSec)
                    .GreaterThan(0);

                val.ValidateAndThrow(this);
            }
        }

        private record class AuthenticationInfo
        {
            [JsonPropertyName("sub")]
            public string? EmailAddress { get; init; }

            [JsonPropertyName("keyid")]
            public string? KeyId { get; init; }

            [JsonPropertyName("serial")]
            public string? SerialNumber { get; init; }

            [JsonPropertyName("data")]
            public string? SignedPubkey { get; init; }

            [JsonPropertyName("site")]
            public string? SiteOrigin { get; init; }

            public static IValidator<AuthenticationInfo> GetValidator()
            {
                InlineValidator<AuthenticationInfo> val = new();

                val.RuleFor(l => l.EmailAddress)
                    .NotEmpty()
                    .Length(5, 100)
                    .EmailAddress();

                val.RuleFor(l => l.SerialNumber)
                    .NotEmpty()
                    .Length(5, 50)
                    .AlphaNumericOnly();

                val.RuleFor(l => l.KeyId)
                    .NotEmpty()
                    .Length(2, 50)
                    .AlphaNumericOnly();

                //Optional signed public key
                val.RuleFor(l => l.SignedPubkey)
                    .Length(64, 500)
                    .IllegalCharacters()
                    .When(l => l.SignedPubkey is not null);

                return val;
            }
        }
    }

}