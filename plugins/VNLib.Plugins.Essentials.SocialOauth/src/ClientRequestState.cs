/*
* Copyright (c) 2022 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.SocialOauth
* File: ClientRequestState.cs 
*
* ClientRequestState.cs is part of VNLib.Plugins.Essentials.SocialOauth which is part of the larger 
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

using VNLib.Hashing;
using VNLib.Utils;
using VNLib.Utils.Memory;
using VNLib.Utils.Memory.Caching;

namespace VNLib.Plugins.Essentials.SocialOauth
{
    internal sealed class ClientRequestState : ICacheable
    {
        private readonly ReadOnlyMemory<byte> _rawKey;

        /// <summary>
        /// The raw nonce state bytes
        /// </summary>
        public ReadOnlyMemory<byte> State { get; private set; }

        public ClientRequestState(ReadOnlySpan<char> keyChar, int nonceBytes)
        {
            //Get browser id 
            _rawKey = Convert.FromHexString(keyChar);
            RecomputeState(nonceBytes);
        }

        /// <summary>
        /// Recomputes a nonce state and signature for the current 
        /// connection
        /// </summary>
        /// <param name="nonceBytes">The size of the nonce (in bytes) to generate</param>
        public void RecomputeState(int nonceBytes)
        {
            //Get random nonce buffer
            State = RandomHash.GetRandomBytes(nonceBytes);
        }
        /// <summary>
        /// Computes the signature of the supplied data based on the original
        /// client state for this connection
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public ERRNO ComputeSignatureForClient(ReadOnlySpan<byte> data, Span<byte> output)
        {
            return HMACSHA512.TryHashData(_rawKey.Span, data, output, out int count) ? count : ERRNO.E_FAIL;
        }

        public DateTime Expires { get; set; }
        bool IEquatable<ICacheable>.Equals(ICacheable other) => ReferenceEquals(this, other);
        void ICacheable.Evicted() 
        {
            //Zero secrets on eviction
            Memory.UnsafeZeroMemory(State);
            Memory.UnsafeZeroMemory(_rawKey);
        }
    }
}