/*
* Copyright (c) 2022 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.SocialOauth
* File: ClientAccessTokenState.cs 
*
* ClientAccessTokenState.cs is part of VNLib.Plugins.Essentials.SocialOauth which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.SocialOauth is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.SocialOauth is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

using System;
using System.Security.Cryptography;
using System.Text.Json.Serialization;

using VNLib.Hashing;
using VNLib.Utils.Memory;
using VNLib.Utils.Memory.Caching;
using VNLib.Plugins.Essentials.Accounts;

#nullable enable

namespace VNLib.Plugins.Essentials.SocialOauth
{
    public sealed class OAuthAccessState : IOAuthAccessState, ICacheable, INonce
    {
        ///<inheritdoc/>
        [JsonPropertyName("access_token")]
        public string? Token { get; set; }
        ///<inheritdoc/>
        [JsonPropertyName("scope")]
        public string? Scope { get; set; }
        ///<inheritdoc/>
        [JsonPropertyName("token_type")]
        public string? Type { get; set; }
        ///<inheritdoc/>
        [JsonPropertyName("refresh_token")]
        public string? RefreshToken { get; set; }
        ///<inheritdoc/>
        [JsonPropertyName("id_token")]
        public string? IdToken { get; set; }
        
        //Ignore the public key and client ids
        [JsonIgnore]
        internal string? PublicKey { get; set; }
        [JsonIgnore]
        internal string? ClientId { get; set; }

        /// <summary>
        /// A random nonce generated when the access state is created and 
        /// deleted when then access token is evicted.
        /// </summary>
        [JsonIgnore]
        internal ReadOnlyMemory<byte> Nonce { get; private set; }

        DateTime ICacheable.Expires { get; set; }
        bool IEquatable<ICacheable>.Equals(ICacheable? other) => GetHashCode() == other?.GetHashCode();
        public override int GetHashCode() => Token!.GetHashCode();
        void ICacheable.Evicted()
        {
            Memory.UnsafeZeroMemory(Nonce);
        }

        void INonce.ComputeNonce(Span<byte> buffer)
        {
            //Compute nonce
            RandomHash.GetRandomBytes(buffer);
            //Copy and store
            Nonce = buffer.ToArray();
        }

        bool INonce.VerifyNonce(ReadOnlySpan<byte> nonceBytes) => CryptographicOperations.FixedTimeEquals(Nonce.Span, nonceBytes);
    }
}