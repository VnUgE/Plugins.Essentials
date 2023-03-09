/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: MFAConfig.cs 
*
* MFAConfig.cs is part of VNLib.Plugins.Essentials.Accounts which is part of the larger 
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
using System.Text.Json.Serialization;

using FluentValidation;

using VNLib.Hashing;
using VNLib.Plugins.Extensions.Loading;

namespace VNLib.Plugins.Essentials.Accounts.MFA
{   

    [ConfigurationName("mfa")]
    internal class MFAConfig : IOnConfigValidation
    {
        private static IValidator<MFAConfig> GetValidator()
        {
            InlineValidator<MFAConfig> val = new();

            val.RuleFor(c => c.UpgradeExpSeconds)
                .GreaterThan(1)
                .WithMessage("You must configure a non-zero upgrade expiration timeout");

            val.RuleFor(c => c.NonceLenBytes)
                .GreaterThanOrEqualTo(8)
                .WithMessage("You must configure a nonce size of 8 bytes or larger");

            val.RuleFor(c => c.UpgradeKeyBytes)
                .GreaterThanOrEqualTo(8)
                .WithMessage("You must configure a signing key size of 8 bytes or larger");

            return val;
        }

        private static IValidator<MFAConfig> _validator { get; } = GetValidator();

        [JsonPropertyName("totp")]
        public TOTPConfig? TOTPConfig { get; set; }

        [JsonIgnore]
        public bool TOTPEnabled => TOTPConfig?.IssuerName != null;

        [JsonPropertyName("fido")]
        public FidoConfig? FIDOConfig { get; set; }

        [JsonIgnore]
        public bool FIDOEnabled => FIDOConfig?.FIDOSiteName != null;

        [JsonIgnore]
        public TimeSpan UpgradeValidFor { get; private set; } = TimeSpan.FromSeconds(120);

        [JsonPropertyName("upgrade_expires_secs")]
        public int UpgradeExpSeconds
        {
            get => (int)UpgradeValidFor.TotalSeconds;
            set => UpgradeValidFor = TimeSpan.FromSeconds(value);
        }

        [JsonPropertyName("nonce_size")]
        public int NonceLenBytes { get; set; } = 16;
        [JsonPropertyName("upgrade_size")]
        public int UpgradeKeyBytes { get; set; } = 32;
      

        public void Validate()
        {
            //Validate the current confige before child configs
            _validator.ValidateAndThrow(this);

            TOTPConfig?.Validate();
            FIDOConfig?.Validate();
        }
    }

    internal class TOTPConfig : IOnConfigValidation
    {
        private static IValidator<TOTPConfig> GetValidator()
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

        [JsonIgnore]
        private static IValidator<TOTPConfig> _validator { get; } = GetValidator(); 

        [JsonPropertyName("issuer")]
        public string? IssuerName { get; set; }

        [JsonPropertyName("period_sec")]
        public int PeriodSec
        {
            get => (int)TOTPPeriod.TotalSeconds;
            set => TOTPPeriod = TimeSpan.FromSeconds(value);
        }
        [JsonIgnore]
        public TimeSpan TOTPPeriod { get; set; } = TimeSpan.FromSeconds(30);
      

        [JsonPropertyName("algorithm")]
        public string AlgName
        {
            get => TOTPAlg.ToString();
            set => TOTPAlg = Enum.Parse<HashAlg>(value.ToUpper(null));
        }
        [JsonIgnore]
        public HashAlg TOTPAlg { get; set; } = HashAlg.SHA1;

        [JsonPropertyName("digits")]
        public int TOTPDigits { get; set; } = 6;

        [JsonPropertyName("secret_size")]
        public int TOTPSecretBytes { get; set; } = 32;

        [JsonPropertyName("window_size")]
        public int TOTPTimeWindowSteps { get; set; } = 1;

        public void Validate()
        {
            //Validate the current instance on the 
            _validator.ValidateAndThrow(this);
        }
    }

    internal class FidoConfig : IOnConfigValidation
    {
        private static IValidator<FidoConfig> GetValidator()
        {
            InlineValidator<FidoConfig> val = new();


            return val; 
        }

        private static IValidator<FidoConfig> _validator { get; } = GetValidator();

     
        public int FIDOChallangeSize { get; }
        public int FIDOTimeout { get; }
        public string? FIDOSiteName { get; }
        public string? FIDOAttestationType { get; }
        public FidoAuthenticatorSelection? FIDOAuthSelection { get; }

        public void Validate()
        {
            _validator.ValidateAndThrow(this);
        }
    }
}
