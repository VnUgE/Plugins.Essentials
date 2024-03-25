/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: AccountSecConfig.cs 
*
* AccountSecConfig.cs is part of VNLib.Plugins.Essentials.Accounts which is part 
* of the larger VNLib collection of libraries and utilities.
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
using System.Text.Json.Serialization;

using FluentValidation;

using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Validation;

namespace VNLib.Plugins.Essentials.Accounts.SecurityProvider
{
    internal sealed class AccountSecConfig : IOnConfigValidation
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
}
