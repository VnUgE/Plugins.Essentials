﻿/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: FidoAuthenticatorAssertionResponse.cs 
*
* FidoAuthenticatorAssertionResponse.cs is part of VNLib.Plugins.Essentials.Accounts 
* which is part of the larger VNLib collection of libraries and utilities.
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
    internal sealed class FidoAuthenticatorAssertionResponse
    {
        [JsonPropertyName("authenticatorData")]
        public string Base64UrlAuthData { get; set; } = string.Empty;

        [JsonPropertyName("clientDataJSON")]
        public string Base64UrlClientData { get; set; } = string.Empty;

        [JsonPropertyName("signature")]
        public string Base64UrlSignature { get; set; } = string.Empty;
    }
}
