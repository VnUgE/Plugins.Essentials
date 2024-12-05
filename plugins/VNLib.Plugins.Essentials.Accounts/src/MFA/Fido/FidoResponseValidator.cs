/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: FidoResponseValidator.cs 
*
* FidoResponseValidator.cs is part of VNLib.Plugins.Essentials.Accounts which 
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
using FluentValidation;

using VNLib.Plugins.Essentials.Accounts.MFA.Fido.JsonTypes;

namespace VNLib.Plugins.Essentials.Accounts.MFA.Fido
{
    internal sealed class FidoResponseValidator : AbstractValidator<FidoAuthenticatorResponse>
    {
        public FidoResponseValidator()
        {
            RuleFor(c => c.DeviceId)
                .NotEmpty()
                .WithMessage("Fido 'device_id' must be provided")
                .MaximumLength(256);

            RuleFor(c => c.DeviceName)
                .NotEmpty()
                .Matches(@"^[a-zA-Z0-9\s]+$")
                .WithMessage("Your device name contains invalid characters")
                .MaximumLength(64);

            RuleFor(c => c.Base64PublicKey)
                .NotEmpty()
                .WithMessage("Fido 'public_key' must be provided");

            RuleFor(c => c.CoseAlgorithmNumber)
                .NotNull()
                .WithMessage("Fido 'public_key_algorithm' number must be provided in a valid COSE algorithm number");

            RuleFor(c => c.Base64ClientData)
                .NotEmpty()
                .WithMessage("Fido 'client_data' must be provided")
                .MaximumLength(4096);

            RuleFor(c => c.Base64AuthenticatorData)
                .NotEmpty()
                .WithMessage("Fido 'authenticator_data' must be provided")
                .MaximumLength(4096);

            RuleFor(c => c.Base64Attestation)
                .NotEmpty()
                .WithMessage("Fido 'attestation' must be provided")
                .MaximumLength(4096);

        }

    }
}