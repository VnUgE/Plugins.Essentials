/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: FidoRegistrationMessage.cs 
*
* FidoRegistrationMessage.cs is part of VNLib.Plugins.Essentials.Accounts which is part of the larger 
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

using System.Text.Json.Serialization;

namespace VNLib.Plugins.Essentials.Accounts.MFA.Fido
{
    /// <summary>
    /// Represents a fido device registration message to be sent
    /// to a currently signed in user
    /// </summary>
    sealed class FidoRegistrationMessage
    {
        [JsonPropertyName("challenge")]
        public string? Base64Challenge { get; set; } = null;

        [JsonPropertyName("timeout")]
        public int Timeout { get; set; } = 60000;

        [JsonPropertyName("rp")]
        public FidoRelyingParty RelyingParty { get; set; } = new();

        [JsonPropertyName("attestation")]
        public string? AttestationType { get; set; } = "none";

        [JsonPropertyName("user")]
        public FidoUserData User { get; set; } = new();

        [JsonPropertyName("pubKeyCredParams")]
        public FidoPubkeyAlgorithm[]? PubKeyCredParams { get; set; }

        [JsonPropertyName("authenticatorSelection")]
        public FidoAuthenticatorSelection? AuthSelection { get; set; } = new();
    }
}
