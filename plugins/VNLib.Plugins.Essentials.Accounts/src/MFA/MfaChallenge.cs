/*
* Copyright (c) 2025 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: MfaChallenge.cs 
*
* MfaChallenge.cs is part of VNLib.Plugins.Essentials.Accounts which is part of the larger 
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

namespace VNLib.Plugins.Essentials.Accounts.MFA
{
    internal sealed class MfaChallenge : IClientSecInfo
    {
        /// <summary>
        /// The login's client id specifier
        /// </summary>
        [JsonPropertyName("cid")]
        public string? ClientId { get; set; }

        /// <summary>
        /// The id of the user that is requesting a login
        /// </summary>
        [JsonPropertyName("uname")]
        public string? UserName { get; set; }

        /// <summary>
        /// The supported mfa types enabled for the user
        /// </summary>
        [JsonPropertyName("types")]
        public string[] Types { get; set; }

        /// <summary>
        /// The a base64 encoded string of the user's 
        /// public key
        /// </summary>
        [JsonPropertyName("pubkey")]
        public string? PublicKey { get; set; }

        /// <summary>
        /// The user's specified language
        /// </summary>
        [JsonPropertyName("lang")]
        public string? ClientLocalLanguage { get; set; }
    }
}
