/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Auth.Social
* File: LoginClaim.cs 
*
* LoginClaim.cs is part of VNLib.Plugins.Essentials.Auth.Social which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Auth.Social is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Auth.Social is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

using System.Text.Json.Serialization;

using VNLib.Hashing;
using VNLib.Utils;
using VNLib.Utils.Memory;
using VNLib.Plugins.Essentials.Accounts;

namespace VNLib.Plugins.Essentials.Auth.Social
{
    internal sealed class LoginClaim : IClientSecInfo
    {
        [JsonPropertyName("exp")]
        public long ExpirationSeconds { get; set; }

        [JsonPropertyName("iat")]
        public long IssuedAtTime { get; set; }

        [JsonPropertyName("nonce")]
        public string? Nonce { get; set; }

        [JsonPropertyName("locallanguage")]
        public string? LocalLanguage { get; set; }

        [JsonPropertyName("pubkey")]
        public string? PublicKey { get; set; }

        [JsonPropertyName("clientid")]
        public string? ClientId { get; set; }


        public void ComputeNonce(int nonceSize)
        {
            //Alloc nonce buffer
            using UnsafeMemoryHandle<byte> buffer = MemoryUtil.UnsafeAlloc(nonceSize);
            try
            {
                //fill the buffer with random data
                RandomHash.GetRandomBytes(buffer.Span);

                //Base32-Encode nonce and save it
                Nonce = VnEncoding.ToBase64UrlSafeString(buffer.Span, false);
            }
            finally
            {
                MemoryUtil.InitializeBlock(buffer.Span);
            }
        }
    }
}
