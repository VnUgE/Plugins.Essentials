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

using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Essentials.Accounts.MFA.Fido.JsonTypes;


namespace VNLib.Plugins.Essentials.Accounts.MFA.Fido
{

    internal sealed class FidoConfig: IOnConfigValidation
    {

        /// <summary>
        /// The size in bytes of the challenge to be sent 
        /// to the authenticator.
        /// </summary>
        [JsonPropertyName("challenge_size")]
        public int ChallangeSize { get; set; }

        /// <summary>
        /// The time (in milliseconds) for the authenicator to
        /// respond to the challenge.
        /// </summary>
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

        /// <summary>
        /// Requires that authenticators return the same origin as the 
        /// server that issued the login request. The origin will be signed
        /// by the authenticator and verified by the server.
        /// </summary>
        [JsonPropertyName("strict_origin")]
        public bool StrictOrigin { get; set; } = true;

        /// <summary>
        /// Allows the user to call the 'disable_all' RPC method for 
        /// fido devices
        /// </summary>
        [JsonPropertyName("allow_disable_all")]
        public bool AllowDisableAllRpcCall { get; set; } = false;

        ///<inheritdoc/>
        public void OnValidate()
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
                .WithMessage("Fido 'attestation_type' must be provided")
                .Must(type => type == "none" || type == "direct")
                .WithMessage("Fido 'attestation_type' must be 'none' or 'direct' ('indirect' is no longer supported in WebAuthn L3)");

            val.RuleFor(c => c.FIDOAuthSelection)
                .NotNull()
                .WithMessage("Fido 'authenticator_selection' must be provided");

            val.RuleFor(c => c.Transports)
                .NotEmpty()
                .ForEach(p => p.NotEmpty())
                .WithMessage("Fido 'transport' must be provided");

            val.ValidateAndThrow(this);
        }
    }
}
