/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: UserFidoMfaExtensions.cs 
*
* UserFidoMfaExtensions.cs is part of VNLib.Plugins.Essentials.Accounts which is part of the larger 
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

using System;
using System.Buffers.Binary;
using System.Formats.Cbor;

using VNLib.Utils;
using VNLib.Utils.Memory;

namespace VNLib.Plugins.Essentials.Accounts.MFA.Fido
{
    internal static class FidoDecoder
    {
        public static FidoDeviceCredential? FromResponse(FidoAuthenticatorResponse response)
        {
            //Make sure the response has a public key and a valid algorithm
            if (!response.CoseAlgorithmNumber.HasValue || string.IsNullOrWhiteSpace(response.Base64PublicKey))
            {
                return null;
            }

            if(!VerifyKeySizes(response.CoseAlgorithmNumber.Value, response.Base64PublicKey))
            {
                return null;
            }

            return new FidoDeviceCredential
            {
                Base64UrlId = response.DeviceId,
                CoseAlgId = response.CoseAlgorithmNumber.Value,
                Base64PublicKey = response.Base64PublicKey,
                Name = response.DeviceName ?? string.Empty
            };
        }
       

        private static bool VerifyKeySizes(int algCode, string pubkey)
        {
            using UnsafeMemoryHandle<byte> binBuffer = MemoryUtil.UnsafeAlloc<byte>(pubkey.Length + 16, true);

            ERRNO decoded = VnEncoding.Base64UrlDecode(pubkey, binBuffer.Span);

            if(!decoded)
            {
                return false;
            }

            Span<byte> guid = binBuffer.AsSpan(0, 16);
            Span<byte> lenBin = binBuffer.AsSpan(16, 2);

            ushort idLen = BinaryPrimitives.ReadUInt16LittleEndian(lenBin);
            
            //Id length is outside the size of the buffer
            if(idLen + 18 > decoded)
            {
                return false;
            }

            Span<byte> key = binBuffer.AsSpan(18, idLen);
            Span<byte> pubKey = binBuffer.AsSpan(18 + idLen);   //Finally the actual public key length

            return pubKey.Length == CoseEncodings.GetPublicKeySizeForAlg(algCode);
        }
    }
}
