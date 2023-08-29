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
        private static IValidator<ReadOnlyJsonWebKey> UserJwkValidator { get; } = GetKeyValidator();

        private readonly JwtEndpointConfig _config;
        private readonly IUserManager _users;


        /*
         * Default protections sessions should be fine (most strict)
         * No cross-site/cross origin/bad referrer etc
         */
        //protected override ProtectionSettings EndpointProtectionSettings { get; } = new();
        

        public PkiLoginEndpoint(PluginBase plugin, IConfigScope config)
        {
            string? path = config["path"].GetString();
            InitPathAndLog(path, plugin.Log);

            //Load config
            _config = config.DeserialzeAndValidate<JwtEndpointConfig>();
            _users = plugin.GetOrCreateSingleton<UserManager>();

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
                entity.CloseResponse(HttpStatusCode.Conflict);
                return VfReturnType.VirtualSkip;
            }

            ValErrWebMessage webm = new();

            //Get the login message from the client
            JwtLoginMessage? login = await entity.GetJsonFromFileAsync<JwtLoginMessage>();

            if(webm.Assert(login != null, INVALID_MESSAGE))
            {
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }

            //Validate login message
            if(!LwValidator.Validate(login, webm))
            {
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
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
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }
            catch (FormatException)
            {
                webm.Result = INVALID_MESSAGE;
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }

            try
            {
                AuthenticationInfo authInfo;

                //Get the signed payload message
                using (JsonDocument payload = jwt.GetPayload())
                {
                    long unixSec = payload.RootElement.GetProperty("iat").GetInt64();

                    DateTimeOffset clientIat = DateTimeOffset.FromUnixTimeSeconds(unixSec);

                    if (clientIat.Add(_config.MaxJwtTimeDifference) < entity.RequestedTimeUtc)
                    {
                        webm.Result = INVALID_MESSAGE;
                        entity.CloseResponse(webm);
                        return VfReturnType.VirtualSkip;
                    }

                    if (clientIat.Subtract(_config.MaxJwtTimeDifference) > entity.RequestedTimeUtc)
                    {
                        webm.Result = INVALID_MESSAGE;
                        entity.CloseResponse(webm);
                        return VfReturnType.VirtualSkip;
                    }

                    //Recover the authenticator information
                    authInfo = new()
                    {
                        EmailAddress = payload.RootElement.GetPropString("sub"),
                        KeyId = payload.RootElement.GetPropString("keyid"),
                        SerialNumber = payload.RootElement.GetPropString("serial"),
                    };
                }

                //Validate auth info
                if (!AuthValidator.Validate(authInfo, webm))
                {
                    entity.CloseResponse(webm);
                    return VfReturnType.VirtualSkip;
                }

                //Get the user from the email address
                user = await _users.GetUserFromEmailAsync(authInfo.EmailAddress!, entity.EventCancellation);

                if (webm.Assert(user != null, INVALID_MESSAGE))
                {
                    entity.CloseResponse(webm);
                    return VfReturnType.VirtualSkip;
                }

                //Check failed login count
                if(webm.Assert(UserLoginLocked(user, entity.RequestedTimeUtc) == false, INVALID_MESSAGE))
                {
                    entity.CloseResponse(webm);
                    return VfReturnType.VirtualSkip;
                }

                //Now we can verify the signed message against the stored key
                if (webm.Assert(user.PKIVerifyUserJWT(jwt, authInfo.KeyId) == true, INVALID_MESSAGE))
                {
                    //increment flc on invalid signature
                    user.FailedLoginIncrement(entity.RequestedTimeUtc);
                    await user.ReleaseAsync();

                    entity.CloseResponse(webm);
                    return VfReturnType.VirtualSkip;
                }

                //Account status must be active
                if(webm.Assert(user.Status == UserStatus.Active, INVALID_MESSAGE))
                {
                    entity.CloseResponse(webm);
                    return VfReturnType.VirtualSkip;
                }

                //Must be local account
                if (webm.Assert(user.IsLocalAccount(), INVALID_MESSAGE))
                {
                    entity.CloseResponse(webm);
                    return VfReturnType.VirtualSkip;
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

                //Close response, user is now logged-in
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }
            catch
            {
                entity.InvalidateLogin();
                throw;
            }
            finally
            {
                user?.Dispose();
                jwt.Dispose();
            }          
        }

        /*
         * This endpoint also enables 
         */
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
                entity.CloseResponse(HttpStatusCode.Unauthorized);
                return VfReturnType.VirtualSkip;
            }

            ValErrWebMessage webm = new();

            //Get the request body
            using JsonDocument? request = await entity.GetJsonFromFileAsync();

            if(webm.Assert(request != null, "The request message is not valid"))
            {
                entity.CloseResponseJson(HttpStatusCode.UnprocessableEntity, webm);
                return VfReturnType.VirtualSkip;
            }

            //Get the jwk from the request body
            using ReadOnlyJsonWebKey jwk = new(request.RootElement);

            //Validate the user's jwk
            if(!UserJwkValidator.Validate(jwk, webm))
            {
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }

            //Get the user account
            using IUser? user = await _users.GetUserFromIDAsync(entity.Session.UserID, entity.EventCancellation);

            //Confirm not null, this should only happen if user is removed from table while still logged in
            if(webm.Assert(user != null, "You may not configure PKI authentication"))
            {
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }

            //Local account is required
            if (webm.Assert(user.IsLocalAccount(), "You do not have a local account, you may not configure PKI authentication"))
            {
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }

            try
            {
                //Try to get the ECDA instance to confirm the key data could be recovered properly
                using ECDsa? testAlg = jwk.GetECDsaPublicKey();

                if (webm.Assert(testAlg != null, "Your JWK is not valid"))
                {
                    webm.Result = "Your JWK is not valid";
                    entity.CloseResponse(webm);
                    return VfReturnType.VirtualSkip;
                }
            }
            catch(Exception ex) 
            {
                Log.Debug(ex);
                webm.Result = "Your JWK is not valid";
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }

            //Extract the user's EC key minimum parameters 
            IReadOnlyDictionary<string, string> keyParams = ExtractKeyData(jwk);

            //Update user's key params
            user.PKISetUserKey(keyParams);

            //publish changes
            await user.ReleaseAsync();

            webm.Result = "Successfully updated your PKI authentication method";
            webm.Success = true;
            entity.CloseResponse(webm);
            return VfReturnType.VirtualSkip;
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
                entity.CloseResponse(HttpStatusCode.Unauthorized);
                return VfReturnType.VirtualSkip;
            }

            ValErrWebMessage webm = new();

            //Get the user account
            using IUser? user = await _users.GetUserFromIDAsync(entity.Session.UserID, entity.EventCancellation);

            //Confirm not null, this should only happen if user is removed from table while still logged in
            if (webm.Assert(user != null, "You may not configure PKI authentication"))
            {
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }

            //Local account is required
            if (webm.Assert(user.IsLocalAccount(), "You do not have a local account, you may not configure PKI authentication"))
            {
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }

            //Remove the key
            user.PKISetUserKey(null);
            await user.ReleaseAsync();

            webm.Result = "You have successfully disabled PKI login";
            webm.Success = true;
            entity.CloseResponse(webm);
            return VfReturnType.VirtualSkip;
        }

        public bool UserLoginLocked(IUser user, DateTimeOffset now)
        {
            //Recover last counter value
            TimestampedCounter flc = user.FailedLoginCount();

            if (flc.Count < _config.MaxFailedLogins)
            {
                //Period exceeded
                return false;
            }

            //See if the flc timeout period has expired
            if (flc.LastModified.AddSeconds(_config.FailedCountTimeoutSec) < now)
            {
                //clear flc flag
                user.ClearFailedLoginCount();
                return false;
            }

            //Count has been exceeded, and has not timed out yet
            return true;
        }

        private static IReadOnlyDictionary<string, string> ExtractKeyData(ReadOnlyJsonWebKey key)
        {
            Dictionary<string, string> keyData = new();

            keyData["kty"] = key.KeyType!;
            keyData["use"] = "sig";
            keyData["crv"] = key.GetKeyProperty("crv")!;
            keyData["kid"] = key.KeyId!;
            keyData["alg"] = key.Algorithm!;
            keyData["x"] = key.GetKeyProperty("x")!;
            keyData["y"] = key.GetKeyProperty("y")!;

            return keyData;
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

        private static IValidator<ReadOnlyJsonWebKey> GetKeyValidator()
        {
            InlineValidator<ReadOnlyJsonWebKey> val = new();

            val.RuleFor(a => a.KeyType)
                .NotEmpty()
                .Must(kt => "EC".Equals(kt, StringComparison.Ordinal))
                .WithMessage("The supplied key is not an EC curve key");

            val.RuleFor(a => a.Use)
                .NotEmpty()
                .Must(u => "sig".Equals(u, StringComparison.OrdinalIgnoreCase))
                .WithMessage("Your key must be configured for signatures");

            val.RuleFor(a => a.GetKeyProperty("crv"))
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
                .Must(a => AllowedAlgs.Contains(a, StringComparer.Ordinal))
                .WithMessage("Your key's signature algorithm is not supported");

            //Confirm the x axis parameter is valid
            val.RuleFor(a => a.GetKeyProperty("x"))
                .NotEmpty()
                .WithName("x")
                .Length(10, 200)
                .WithMessage("Your key's X EC point public key parameter is not valid")
                .IllegalCharacters()
                .WithMessage("Your key's X EC point public key parameter conatins invaid characters");


            //Confirm the y axis point is valid
            val.RuleFor(a => a.GetKeyProperty("y"))
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