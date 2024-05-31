/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: FidoConfig.cs 
*
* FidoConfig.cs is part of VNLib.Plugins.Essentials.Accounts which is part 
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

using System.Text.Json.Serialization;

using FluentValidation;

namespace VNLib.Plugins.Essentials.Accounts.MFA.Fido
{

    internal sealed class FidoConfig
    {
       
        [JsonPropertyName("challenge_size")]
        public int ChallangeSize { get; set; }

        [JsonPropertyName("timeout")]
        public int Timeout { get; set; }

        [JsonPropertyName("site_name")]
        public string? SiteName { get; set; }

        [JsonPropertyName("attestation_type")]
        public string? AttestationType { get; set; }

        [JsonPropertyName("authenticator_selection")]
        public FidoAuthenticatorSelection? FIDOAuthSelection { get; set; }

        [JsonPropertyName("transport")]
        public string[] Transports { get; set; } = ["usb", "nfc", "ble"];

        internal static IValidator<FidoConfig> GetValidator()
        {
            InlineValidator<FidoConfig> val = new();

            val.RuleFor(c => c.ChallangeSize)
                .InclusiveBetween(1, 4096)
                .WithMessage("Fido 'challenge_size' must be between 1 and 4096 bytes");

            val.RuleFor(c => c.Timeout)
                .InclusiveBetween(1, int.MaxValue)
                .WithMessage("Fido 'timeout' must be between 1 and 600 seconds");

            val.RuleFor(c => c.SiteName)
                .NotEmpty()
                .WithMessage("Fido 'site_name' must be provided");

            val.RuleFor(c => c.AttestationType)
                .NotEmpty()
                .WithMessage("Fido 'attestation_type' must be provided");

            val.RuleFor(c => c.FIDOAuthSelection)
                .NotNull()
                .WithMessage("Fido 'authenticator_selection' must be provided");

            val.RuleFor(c => c.Transports)
                .NotEmpty()
                .ForEach(p => p.NotEmpty())
                .WithMessage("Fido 'transport' must be provided");

            return val;
        }
    }
}
