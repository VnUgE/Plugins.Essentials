/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: PkiAuthPublicKey.cs 
*
* PkiAuthPublicKey.cs is part of VNLib.Plugins.Essentials.Accounts which is part of the larger 
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

using VNLib.Hashing.IdentityUtility;

namespace VNLib.Plugins.Essentials.Accounts.MFA
{
    /// <summary>
    /// A json serializable JWK format public key for PKI authentication
    /// </summary>
    public record class PkiAuthPublicKey : IJsonWebKey
    {
        [JsonPropertyName("kid")]
        public string? KeyId { get; set; }

        [JsonPropertyName("kty")]
        public string? KeyType { get; set; }

        [JsonPropertyName("crv")]
        public string? Curve { get; set; }

        [JsonPropertyName("x")]
        public string? X { get; set; }

        [JsonPropertyName("y")]
        public string? Y { get; set; }

        [JsonPropertyName("alg")]
        public string Algorithm { get; set; } = string.Empty;

        [JsonIgnore]
        public JwkKeyUsage KeyUse => JwkKeyUsage.Signature;

        ///<inheritdoc/>
        public string? GetKeyProperty(string propertyName)
        {
            return propertyName switch
            {
                "kid" => KeyId,
                "kty" => KeyType,
                "crv" => Curve,
                "x" => X,
                "y" => Y,
                "alg" => Algorithm,
                _ => null,
            };
        }
    }
}
