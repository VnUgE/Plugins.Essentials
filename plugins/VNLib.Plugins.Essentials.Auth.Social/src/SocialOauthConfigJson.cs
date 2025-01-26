/*
* Copyright (c) 2025 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Auth.Social
* File: SocialOauthConfigJson.cs 
*
* SocialOauthConfigJson.cs is part of VNLib.Plugins.Essentials.Auth.Social which is 
* part of the larger VNLib collection of libraries and utilities.
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

using System.Text.Json.Serialization;

using FluentValidation;

using VNLib.Plugins.Essentials.Accounts;
using VNLib.Plugins.Extensions.Loading;

namespace VNLib.Plugins.Essentials.Auth.Social
{
    internal sealed class SocialOauthConfigJson : IOnConfigValidation
    {
        /// <summary>
        /// Enables or disables social OAuth login
        /// </summary>
        [JsonPropertyName("enabled")]
        public bool Enabled { get; init; }

        /// <summary>
        /// The time a user's upgrade lasts before it expires
        /// </summary>
        [JsonPropertyName("upgrade_timeout_sec")]
        public int UpgradeTimeoutSec { get; init; } = 300;

        /// <summary>
        /// The size of the signature key used for the upgrade request
        /// </summary>
        [JsonPropertyName("signature_key_size")]
        public int SignatureKeySize { get; init; } = 16;

        /// <summary>
        /// If true, the origin of the upgrade request will be checked
        /// </summary>
        [JsonPropertyName("strict_origin_check")]
        public bool StrictOriginCheck { get; init; } = true;

        /// <summary>
        /// The name of the cookie that stores the upgrade token
        /// </summary>
        [JsonPropertyName("upgrade_cookie_name")]
        public string UpgradeCookieName { get; init; } = null!;

        /// <summary>
        /// A value that indicates whether new users can be created
        /// if they don't exist
        /// </summary>
        [JsonPropertyName("create_new_users")]
        public bool CanCreateUser { get; init; }

        /// <summary>
        /// The default size of a generated password
        /// </summary>
        [JsonPropertyName("default_password_size")]
        public int PasswordSize { get; init; } = 64;

        /// <summary>
        /// The default privilages of a new user
        /// </summary>
        [JsonPropertyName("default_user_privilages")]
        public ulong DefaultUserPrivilages { get; init; } = AccountUtil.MINIMUM_LEVEL;

        /// <summary>
        /// Allowed origins when client is cors enabled
        /// </summary>
        [JsonPropertyName("allowed_cors_origins")]
        public string[] AllowedCorsOrigins { get; init; } = [];

        /// <summary>
        /// A value that indicates if all origins are denied
        /// </summary>
        public bool DenyCorsConnections => AllowedCorsOrigins.Length == 0;

        /// <summary>
        /// If true, all origins are allowed
        /// </summary>
        public bool AllowAllCorsConnections => AllowedCorsOrigins.Length == 1 && AllowedCorsOrigins[0] == "*";

        ///<inheritdoc/>
        public void OnValidate()
        {
            InlineValidator<SocialOauthConfigJson> val = [];

            val.RuleFor(c => c.UpgradeTimeoutSec)
                .InclusiveBetween(10, 3600);

            val.RuleFor(c => c.SignatureKeySize)
                .InclusiveBetween(8, 128);

            val.RuleFor(c => c.AllowedCorsOrigins)
                //May be an origin or a wildcard *
                .ForEach(r => r.Matches(@"^https?://[\w\-.]+(:\d+)?$"))
                .When(a => a.AllowedCorsOrigins?.Length > 0);

            val.RuleFor(c => c.PasswordSize)
                .InclusiveBetween(8, 128)
                .When(c => c.CanCreateUser);

            val.ValidateAndThrow(this);
        }
    }
}
