/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: PkiLoginEndpoint.cs 
*
* PkiLoginEndpoint.cs is part of VNLib.Plugins.Essentials.Accounts which 
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
using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text.Json.Serialization;

using FluentValidation;

using VNLib.Utils;
using VNLib.Utils.Logging;
using VNLib.Utils.Extensions;
using VNLib.Hashing.IdentityUtility;
using VNLib.Plugins.Essentials.Users;
using VNLib.Plugins.Essentials.Endpoints;
using VNLib.Plugins.Essentials.Extensions;
using VNLib.Plugins.Extensions.Validation;
using VNLib.Plugins.Essentials.Accounts.MFA;
using VNLib.Plugins.Essentials.Accounts.Validators;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Users;

namespace VNLib.Plugins.Essentials.Accounts.Endpoints
{
    [ConfigurationName("pki_auth_endpoint")]
    internal sealed class PkiLoginEndpoint : UnprotectedWebEndpoint
    {
        public const string INVALID_MESSAGE = "Your assertion is invalid, please regenerate and try again";

        /*
         * I am only supporting EC keys for size reasons, user objects are limited in back-end size and keys can 
         * take up large ammounts of data.
         */
        private static readonly ImmutableArray<string> AllowedCurves = new string[3] { "P-256", "P-384", "P-521"}.ToImmutableArray();
        private static readonly ImmutableArray<string> AllowedAlgs = new string[3] { "ES256", "ES384", "ES512" }.ToImmutableArray();

        private static JwtLoginValidator LwValidator { get; } = new();
        private static IValidator<AuthenticationInfo> AuthValidator { get; } = AuthenticationInfo.GetValidator();
        
        /// <summary>
        /// A validator used to validate <see cref="PkiAuthPublicKey"/> instances
        /// </summary>
        public static IValidator<PkiAuthPublicKey> UserJwkValidator { get; } = GetKeyValidator();

        private readonly JwtEndpointConfig _config;
        private readonly IUserManager _users;
        private readonly FailedLoginLockout _lockout;
        

        public PkiLoginEndpoint(PluginBase plugin, IConfigScope config)
        {
            string? path = config["path"].GetString();
            InitPathAndLog(path, plugin.Log);

            //Load config
            _config = config.DeserialzeAndValidate<JwtEndpointConfig>();
            _users = plugin.GetOrCreateSingleton<UserManager>();
            _lockout = new((uint)_config.MaxFailedLogins, TimeSpan.FromSeconds(_config.FailedCountTimeoutSec));

            Log.Verbose("PKI endpoint enabled");
        }

        protected override ERRNO PreProccess(HttpEntity entity)
        {
            return base.PreProccess(entity) && !entity.Session.IsNew;
        }

        protected override async ValueTask<VfReturnType> PostAsync(HttpEntity entity)
        {
            //Conflict if user is logged in
            if (entity.IsClientAuthorized(AuthorzationCheckLevel.Any))
            {
                return VirtualClose(entity, HttpStatusCode.Conflict);
            }

            ValErrWebMessage webm = new();

            //Get the login message from the client
            JwtLoginMessage? login = await entity.GetJsonFromFileAsync<JwtLoginMessage>();

            if(webm.Assert(login != null, INVALID_MESSAGE))
            {
                return VirtualOk(entity, webm);
            }

            //Validate login message
            if(!LwValidator.Validate(login, webm))
            {
                return VirtualOk(entity, webm);
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
                webm.Result = INVALID_MESSAGE;
                return VirtualOk(entity, webm);
            }
            catch (FormatException)
            {
                webm.Result = INVALID_MESSAGE;
                return VirtualOk(entity, webm);
            }

            try
            {
                AuthenticationInfo authInfo = default;

                //Get auth info from jwt
                bool isValidAuth = GetAuthInfo(jwt, entity.RequestedTimeUtc, ref authInfo);

                if(webm.Assert(isValidAuth, INVALID_MESSAGE))
                {
                    return VirtualOk(entity, webm);
                }

                //Validate auth info
                if (!AuthValidator.Validate(authInfo, webm))
                {
                    return VirtualOk(entity, webm);
                }

                //Get the user from the email address
                user = await _users.GetUserFromEmailAsync(authInfo.EmailAddress!, entity.EventCancellation);

                if (webm.Assert(user != null, INVALID_MESSAGE))
                {
                    return VirtualOk(entity, webm);
                }

                //Check failed login count
                if(webm.Assert(_lockout.CheckOrClear(user, entity.RequestedTimeUtc) == false, INVALID_MESSAGE))
                {
                    return VirtualOk(entity, webm);
                }

                //Now we can verify the signed message against the stored key
                if (webm.Assert(user.PKIVerifyUserJWT(jwt, authInfo.KeyId!) == true, INVALID_MESSAGE))
                {
                    //increment flc on invalid signature
                    _lockout.Increment(user, entity.RequestedTimeUtc);
                    await user.ReleaseAsync();

                    return VirtualOk(entity, webm);
                }

                //Account status must be active
                if(webm.Assert(user.Status == UserStatus.Active, INVALID_MESSAGE))
                {
                    return VirtualOk(entity, webm);
                }

                //Must be local account
                if (webm.Assert(user.IsLocalAccount(), INVALID_MESSAGE))
                {
                    return VirtualOk(entity, webm);
                }

                //User is has been authenticated

                //Authorize the user
                entity.GenerateAuthorization(login, user, webm);

                //Write user data
                await user.ReleaseAsync();

                webm.Success = true;

                //Return user data
                webm.Result = new AccountData()
                {
                    EmailAddress = user.EmailAddress,
                };

                //Write to log
                Log.Verbose("Successful login for user {uid}...", user.UserID[..8]);

                //Close response, user is now logged-in
                return VirtualOk(entity, webm);
            }
            catch
            {
                /*
                 * If an internal  error occurs after the authorization has been 
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
        }

        protected override async ValueTask<VfReturnType> GetAsync(HttpEntity entity)
        {
            //This endpoint requires valid authorization
            if (!entity.IsClientAuthorized(AuthorzationCheckLevel.Critical))
            {
                return VirtualClose(entity, HttpStatusCode.Unauthorized);
            }

            ValErrWebMessage webm = new();

            //Get current user
            using IUser? user = await _users.GetUserFromIDAsync(entity.Session.UserID);

            if (webm.Assert(user != null, "User account is invalid"))
            {
                return VirtualOk(entity);
            }

            //Get the uesr's stored keys
            webm.Result = user.PkiGetAllPublicKeys();
            webm.Success = true;

            return VirtualOk(entity, webm);
        }
       
        protected override async ValueTask<VfReturnType> PatchAsync(HttpEntity entity)
        {
            //Check for config flag
            if (!_config.EnableKeyUpdate)
            {
                return VfReturnType.Forbidden;
            }
            //This endpoint requires valid authorization
            if (!entity.IsClientAuthorized(AuthorzationCheckLevel.Critical))
            {
                return VirtualClose(entity, HttpStatusCode.Unauthorized);
            }

            ValErrWebMessage webm = new();

            //Get the request body
            PkiAuthPublicKey? pubKey = await entity.GetJsonFromFileAsync<PkiAuthPublicKey>();

            if(webm.Assert(pubKey != null, "The request message is not valid"))
            {                
                return VirtualClose(entity, webm, HttpStatusCode.UnprocessableEntity);
            }

            //Validate the user's jwk
            if(!UserJwkValidator.Validate(pubKey, webm))
            {
                return VirtualOk(entity, webm);
            }

            //Get the user account
            using IUser? user = await _users.GetUserFromIDAsync(entity.Session.UserID, entity.EventCancellation);

            //Confirm not null, this should only happen if user is removed from table while still logged in
            if(webm.Assert(user != null, "You may not configure PKI authentication"))
            {
                return VirtualOk(entity, webm);
            }

            //Local account is required
            if (webm.Assert(user.IsLocalAccount(), "You do not have a local account, you may not configure PKI authentication"))
            {
                return VirtualOk(entity, webm);
            }

            try
            {
                //Try to get the ECDA instance to confirm the key data could be recovered properly
                using ECDsa? testAlg = pubKey.GetECDsaPublicKey();

                if (webm.Assert(testAlg != null, "Your JWK is not valid"))
                {
                    webm.Result = "Your JWK is not valid";
                    return VirtualOk(entity, webm);
                }
            }
            catch(Exception ex) 
            {
                Log.Debug(ex);
                webm.Result = "Your JWK is not valid";
                return VirtualOk(entity, webm);
            }            

            //Update user's key, or add it if it doesn't exist
            user.PKIAddPublicKey(pubKey);

            //publish changes
            await user.ReleaseAsync();

            webm.Result = "Successfully updated your PKI authentication method";
            webm.Success = true;
            return VirtualOk(entity, webm);
        }

        protected override async ValueTask<VfReturnType> DeleteAsync(HttpEntity entity)
        {
            //Check for config flag
            if (!_config.EnableKeyUpdate)
            {
                return VfReturnType.Forbidden;
            }

            //This endpoint requires valid authorization
            if (!entity.IsClientAuthorized(AuthorzationCheckLevel.Critical))
            {
                return VirtualClose(entity, HttpStatusCode.Unauthorized);
            }

            ValErrWebMessage webm = new();

            //Get the user account
            using IUser? user = await _users.GetUserFromIDAsync(entity.Session.UserID, entity.EventCancellation);

            //Confirm not null, this should only happen if user is removed from table while still logged in
            if (webm.Assert(user != null, "You may not configure PKI authentication"))
            {
                return VirtualOk(entity, webm);
            }

            //Local account is required
            if (webm.Assert(user.IsLocalAccount(), "You do not have a local account, you may not configure PKI authentication"))
            {
                return VirtualOk(entity, webm);
            }

            //try to get a single key id to delete
            if(entity.QueryArgs.TryGetValue("id", out string? keyId))
            {
                //Remove only the specified key
                user.PKIRemovePublicKey(keyId);
                webm.Result = "You have successfully removed the key from your account";
            }
            else
            {
                //Delete all keys
                user.PKISetPublicKeys(null);
                webm.Result = "You have successfully disabled PKI login";
            }
         
            await user.ReleaseAsync();

            webm.Success = true;
            return VirtualOk(entity, webm);
        }

        private bool GetAuthInfo(JsonWebToken jwt, DateTimeOffset now, ref AuthenticationInfo authInfo)
        {
            //Get the signed payload message
            using JsonDocument payload = jwt.GetPayload();

            long unixSec = payload.RootElement.GetProperty("iat").GetInt64();

            DateTimeOffset clientIat = DateTimeOffset.FromUnixTimeSeconds(unixSec);

            if (clientIat.Add(_config.MaxJwtTimeDifference) < now)
            {
                return false;
            }

            if (clientIat.Subtract(_config.MaxJwtTimeDifference) > now)
            {
                return false;
            }

            //Recover the authenticator information
            authInfo = new()
            {
                EmailAddress = payload.RootElement.GetPropString("sub"),
                KeyId = payload.RootElement.GetPropString("keyid"),
                SerialNumber = payload.RootElement.GetPropString("serial"),
            };

            return true;
        }

        private sealed class JwtLoginValidator : ClientSecurityMessageValidator<JwtLoginMessage>
        {
            public JwtLoginValidator() : base()
            {
                //Basic jwt validator
                RuleFor(l => l.LoginJwt)
                    .NotEmpty()
                    .MinimumLength(50)
                    //Token should not contain illegal chars, only base64url + '.'
                    .IllegalCharacters()
                    //Make sure the jwt contains exacly 2 '.' chracters
                    .Must(static l => l.Where(static c => c == '.').Count() == 2)
                    .WithMessage("Your credential is not a valid Json Web Token");
            }
        }

        sealed class JwtLoginMessage : IClientSecInfo
        {
            [JsonPropertyName("pubkey")]
            public string? PublicKey { get; set; }

            [JsonPropertyName("clientid")]
            public string? ClientId { get; set; }

            [JsonPropertyName("login")]
            public string? LoginJwt { get; set; }
        }

        sealed class JwtEndpointConfig : IOnConfigValidation
        {
            [JsonIgnore]
            public TimeSpan MaxJwtTimeDifference { get; set; } = TimeSpan.FromSeconds(30);

            [JsonPropertyName("jwt_time_dif_sec")]
            public uint TimeDiffSeconds
            {
                get => (uint)MaxJwtTimeDifference.TotalSeconds;
                set => TimeSpan.FromSeconds(value);
            }

            [JsonPropertyName("enable_key_update")]
            public bool EnableKeyUpdate { get; set; } = true;

            [JsonPropertyName("max_login_attempts")]
            public int MaxFailedLogins { get; set; } = 10;

            [JsonPropertyName("failed_attempt_timeout_sec")]
            public double FailedCountTimeoutSec { get; set; } = 300;

            public void Validate()
            {
                Validator.ValidateAndThrow(this);
            }

            private static IValidator<JwtEndpointConfig> Validator { get; } = GetValidator();
            private static IValidator<JwtEndpointConfig> GetValidator()
            {
                InlineValidator<JwtEndpointConfig> val = new();

                val.RuleFor(c => c.TimeDiffSeconds)
                    .GreaterThan((uint)1)
                    .WithMessage("You must specify a JWT IAT time difference greater than 0 seconds");

                val.RuleFor(c => c.MaxFailedLogins)
                    .GreaterThan(0);

                val.RuleFor(c => c.FailedCountTimeoutSec)
                    .GreaterThan(0);
                
                return val;
            }

        }

        readonly record struct AuthenticationInfo
        {
            public readonly string? EmailAddress { get; init; }

            public readonly string? KeyId { get; init; }

            public readonly string? SerialNumber { get; init; }

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

                return val;
            }
        }

        private static IValidator<PkiAuthPublicKey> GetKeyValidator()
        {
            InlineValidator<PkiAuthPublicKey> val = new();

            val.RuleFor(a => a.KeyType)
                .NotEmpty()
                .Must(kt => "EC".Equals(kt, StringComparison.Ordinal))
                .WithMessage("The supplied key is not an EC curve key");

            val.RuleFor(a => a.Curve)
                .NotEmpty()
                .WithName("crv")
                .Must(p => AllowedCurves.Contains(p, StringComparer.Ordinal))
                .WithMessage("Your key's curve is not supported");

            val.RuleFor(c => c.KeyId)
                .NotEmpty()
                .Length(10, 100)
                .IllegalCharacters();

            val.RuleFor(a => a.Algorithm)
                .NotEmpty()
                .WithName("alg")
                .Must(a => AllowedAlgs.Contains(a, StringComparer.Ordinal))
                .WithMessage("Your key's signature algorithm is not supported");

            //Confirm the x axis parameter is valid
            val.RuleFor(a => a.X)
                .NotEmpty()
                .WithName("x")
                .Length(10, 200)
                .WithMessage("Your key's X EC point public key parameter is not valid")
                .IllegalCharacters()
                .WithMessage("Your key's X EC point public key parameter conatins invaid characters");

            //Confirm the y axis point is valid
            val.RuleFor(a => a.Y)
                .NotEmpty()
                .WithName("y")
                .Length(10, 200)
                .WithMessage("Your key's Y EC point public key parameter is not valid")
                .IllegalCharacters()
                .WithMessage("Your key's Y EC point public key parameter conatins invaid characters");

            return val;
        }
    }
}