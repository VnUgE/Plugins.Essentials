﻿/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: FidoAuthenticatorResponse.cs 
*
* FidoAuthenticatorResponse.cs is part of VNLib.Plugins.Essentials.Accounts which is part 
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

namespace VNLib.Plugins.Essentials.Accounts.MFA.Fido.JsonTypes
{
    internal sealed class FidoAuthenticatorResponse
    {
        [JsonPropertyName("id")]
        public string DeviceId { get; set; } = string.Empty;

        [JsonPropertyName("publicKey")]
        public string? Base64PublicKey { get; set; }

        [JsonPropertyName("publicKeyAlgorithm")]
        public int? CoseAlgorithmNumber { get; set; }

        [JsonPropertyName("clientDataJSON")]
        public string? Base64ClientData { get; set; }

        [JsonPropertyName("authenticatorData")]
        public string? Base64AuthenticatorData { get; set; }

        [JsonPropertyName("attestationObject")]
        public string? Base64Attestation { get; set; }

        [JsonPropertyName("friendlyName")]
        public string? DeviceName { get; set; }
    }
}
