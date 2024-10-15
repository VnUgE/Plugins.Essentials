/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: MfaConfig.cs 
*
* MfaConfig.cs is part of VNLib.Plugins.Essentials.Accounts which is part of the larger 
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

using VNLib.Plugins.Extensions.Loading;

namespace VNLib.Plugins.Essentials.Accounts.MFA
{
    [ConfigurationName("mfa")]
    internal sealed class MfaConfig : IOnConfigValidation
    {
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


        public void OnValidate()
        {
            InlineValidator<MfaConfig> val = new();

            val.RuleFor(c => c.UpgradeExpSeconds)
                .GreaterThan(1)
                .WithMessage("You must configure a non-zero upgrade expiration timeout");

            val.RuleFor(c => c.NonceLenBytes)
                .GreaterThanOrEqualTo(8)
                .WithMessage("You must configure a nonce size of 8 bytes or larger");

            val.RuleFor(c => c.UpgradeKeyBytes)
                .GreaterThanOrEqualTo(8)
                .WithMessage("You must configure a signing key size of 8 bytes or larger");

            val.ValidateAndThrow(this);
        }
       
    }
}
