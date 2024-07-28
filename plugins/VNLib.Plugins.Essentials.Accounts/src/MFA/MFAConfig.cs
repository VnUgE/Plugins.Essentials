/*
* Copyright (c) 2024 Vaughn Nugent
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
using System.Collections.Generic;
using System.Text.Json.Serialization;

using FluentValidation;

using VNLib.Plugins.Essentials.Accounts.MFA.Fido;
using VNLib.Plugins.Essentials.Accounts.MFA.Totp;
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

            val.RuleFor(c => c.FIDOConfig)
                .SetValidator(FidoConfig.GetValidator()!)
                .When(c => c.FIDOConfig != null);

            val.RuleFor(c => c.TOTPConfig)
                .SetValidator(TOTPConfig.GetValidator()!)
                .When(c => c.TOTPConfig != null);

            return val;
        }

        private static IValidator<MFAConfig> _validator { get; } = GetValidator();

        [JsonPropertyName("totp")]
        public TOTPConfig? TOTPConfig { get; set; }

        [JsonPropertyName("fido")]
        public FidoConfig? FIDOConfig { get; set; }

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

        [JsonIgnore]
        public TimeSpan UpgradeValidFor { get; private set; } = TimeSpan.FromSeconds(120);


        public void OnValidate() => _validator.ValidateAndThrow(this);
    
        public IMfaProcessor[] GetSupportedProcessors()
        {
            List<IMfaProcessor> processors = [];

            if (TOTPConfig?.Enabled == true)
            {
                processors.Add(new TotpAuthProcessor(TOTPConfig!));
            }

            if (FIDOConfig != null)
            {
                processors.Add(new FidoMfaProcessor(FIDOConfig));
            }

            return [.. processors];
        }
    }
}
