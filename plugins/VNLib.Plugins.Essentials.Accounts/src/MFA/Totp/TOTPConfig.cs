/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: TOTPConfig.cs 
*
* TOTPConfig.cs is part of VNLib.Plugins.Essentials.Accounts which is part 
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

using VNLib.Hashing;

namespace VNLib.Plugins.Essentials.Accounts.MFA.Totp
{
    internal sealed class TOTPConfig
    {        
        [JsonPropertyName("issuer")]
        public string? IssuerName { get; set; }

        [JsonPropertyName("period_sec")]
        public int PeriodSec
        {
            get => (int)TOTPPeriod.TotalSeconds;
            set => TOTPPeriod = TimeSpan.FromSeconds(value);
        }

        [JsonPropertyName("algorithm")]
        public string AlgName
        {
            get => TOTPAlg.ToString();
            set => TOTPAlg = Enum.Parse<HashAlg>(value.ToUpper(null));
        }

        [JsonPropertyName("digits")]
        public int TOTPDigits { get; set; } = 6;

        [JsonPropertyName("secret_size")]
        public int TOTPSecretBytes { get; set; } = 32;

        [JsonPropertyName("window_size")]
        public int TOTPTimeWindowSteps { get; set; } = 1;

        [JsonIgnore]
        public bool Enabled => IssuerName != null;

        [JsonIgnore]
        public HashAlg TOTPAlg { get; set; } = HashAlg.SHA1;

        [JsonIgnore]
        public TimeSpan TOTPPeriod { get; set; } = TimeSpan.FromSeconds(30);

        internal static IValidator<TOTPConfig> GetValidator()
        {
            InlineValidator<TOTPConfig> val = new();

            val.RuleFor(c => c.IssuerName)
               .NotEmpty();

            val.RuleFor(c => c.PeriodSec)
                .InclusiveBetween(1, 600);

            val.RuleFor(c => c.TOTPAlg)
                .Must(a => a != HashAlg.None)
                .WithMessage("TOTP Algorithim name must not be NONE");

            val.RuleFor(c => c.TOTPDigits)
                .GreaterThan(1)
                .WithMessage("You should have more than 1 digit for a totp code");

            //We dont neet to check window steps, the user may want to configure 0 or more
            val.RuleFor(c => c.TOTPTimeWindowSteps);

            val.RuleFor(c => c.TOTPSecretBytes)
                .GreaterThan(8)
                .WithMessage("You should configure a larger TOTP secret size for better security");

            return val;
        }

    }
}
