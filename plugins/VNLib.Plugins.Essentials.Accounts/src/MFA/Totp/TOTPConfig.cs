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
using VNLib.Plugins.Extensions.Loading;

namespace VNLib.Plugins.Essentials.Accounts.MFA.Totp
{
    internal sealed class TOTPConfig: IOnConfigValidation
    {        
        [JsonPropertyName("issuer")]
        public string? IssuerName { get; set; }

        [JsonPropertyName("period_sec")]
        public int PeriodSec
        {
            get => (int)Period.TotalSeconds;
            set => Period = TimeSpan.FromSeconds(value);
        }

        [JsonPropertyName("algorithm")]
        public string AlgName
        {
            get => HashAlg.ToString();
            set => HashAlg = Enum.Parse<HashAlg>(value.ToUpper(null));
        }

        [JsonPropertyName("digits")]
        public int Digits { get; set; } = 6;

        [JsonPropertyName("secret_size")]
        public int SecretSize { get; set; } = 32;

        [JsonPropertyName("window_size")]
        public int TimeWindowSteps { get; set; } = 1;

        [JsonIgnore]
        public bool Enabled => IssuerName != null;

        [JsonIgnore]
        public HashAlg HashAlg { get; set; } = HashAlg.SHA1;

        [JsonIgnore]
        public TimeSpan Period { get; set; } = TimeSpan.FromSeconds(30);

        ///<inheritdoc/>
        public void OnValidate()
        {
            if (IssuerName != null)
            {
                IssuerName = IssuerName.Trim();
            }

            GetValidator().ValidateAndThrow(this);
        }


        internal static IValidator<TOTPConfig> GetValidator()
        {
            InlineValidator<TOTPConfig> val = new();

            val.RuleFor(c => c.IssuerName)
               .NotEmpty();

            val.RuleFor(c => c.PeriodSec)
                .InclusiveBetween(1, 600);

            val.RuleFor(c => c.HashAlg)
                .Must(a => a != HashAlg.None)
                .WithMessage("TOTP Algorithim name must not be NONE");

            val.RuleFor(c => c.Digits)
                .GreaterThan(1)
                .WithMessage("You should have more than 1 digit for a totp code")
                .LessThan(10)
                .WithMessage("You should have less than 10 digits for a totp code");

            //We dont neet to check window steps, the user may want to configure 0 or more
            val.RuleFor(c => c.TimeWindowSteps);

            val.RuleFor(c => c.SecretSize)
                .GreaterThan(8)
                .WithMessage("You should configure a larger TOTP secret size for better security");

            return val;
        }       
    }
}
