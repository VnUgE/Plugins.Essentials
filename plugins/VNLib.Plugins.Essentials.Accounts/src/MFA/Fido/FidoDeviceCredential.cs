/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: FidoDeviceCredential.cs 
*
* FidoDeviceCredential.cs is part of VNLib.Plugins.Essentials.Accounts which 
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

using System.Text.Json.Serialization;


namespace VNLib.Plugins.Essentials.Accounts.MFA.Fido
{
    public sealed record class FidoDeviceCredential
    {
        [JsonPropertyName("n")]
        public string Name { get; set; } = string.Empty;

        [JsonPropertyName("alg")]
        public int CoseAlgId { get; set; }

        [JsonPropertyName("id")]
        public string? Base64DeviceId { get; set; }

        [JsonPropertyName("x")]
        public string? Base64XCoord { get; set; }

        [JsonPropertyName("y")]
        public string? Base64YCoord { get; set; }

        /*
         * This validator exists to valide fields that are
         * decoded after the credential format validation 
         * is performed. It's used to protect the storage
         * system even if a key seems to be providing valid 
         * data. It is still possible the user or device sends
         * an overly large device id causing the user to run
         * out of storage or cause server errors when saving 
         * data
         */

        public static IValidator<FidoDeviceCredential> GetValidator()
        {
            InlineValidator<FidoDeviceCredential> validator = new();

            validator.RuleFor(d => d.Name)
                .Length(1, 64)
                .Matches(@"^[a-zA-Z0-9\s\p{P}]+$")
                .WithMessage("Your device name contains invalid characters");

            validator.RuleFor(d => d.Base64DeviceId)
                .Matches(@"^[a-zA-Z0-9\+/=/-]+$")     //Must be base64url encoded
                .MaximumLength(72)
                .WithMessage("Your fido device id is too long to store");

            //The rest of the properties are stored internally

            return validator;
        }
       
    }
}