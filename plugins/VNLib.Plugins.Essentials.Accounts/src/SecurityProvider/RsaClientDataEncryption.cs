/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: RsaClientDataEncryption.cs 
*
* RsaClientDataEncryption.cs is part of VNLib.Plugins.Essentials.Accounts 
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

using System;
using System.Security.Cryptography;

using VNLib.Utils;
using VNLib.Utils.Memory;

namespace VNLib.Plugins.Essentials.Accounts.SecurityProvider
{
    internal static class RsaClientDataEncryption
    {
        /// <summary>
        /// The client data encryption padding. Client library must match this padding
        /// </summary>
        public static readonly RSAEncryptionPadding ClientEncryptonPadding = RSAEncryptionPadding.OaepSHA256;

        /// <summary>
        /// Tries to encrypt the specified data using the specified public key
        /// </summary>
        /// <param name="base64PubKey">A base64 encoded public key used to encrypt client data</param>
        /// <param name="data">Data to encrypt</param>
        /// <param name="outputBuffer">The buffer to store encrypted data in</param>
        /// <returns>
        /// The number of encrypted bytes written to the output buffer,
        /// or false (0) if the operation failed, or if no credential is 
        /// specified.
        /// </returns>
        /// <exception cref="CryptographicException"></exception>
        public static ERRNO TryEncrypt(ReadOnlySpan<char> base64PubKey, ReadOnlySpan<byte> data, Span<byte> outputBuffer)
        {
            if (base64PubKey.IsEmpty)
            {
                return ERRNO.E_FAIL;
            }

            //Alloc a buffer for decoding the public key
            using UnsafeMemoryHandle<byte> pubKeyBuffer = MemoryUtil.UnsafeAllocNearestPage(base64PubKey.Length, true);

            //Decode the public key
            ERRNO pbkBytesWritten = VnEncoding.TryFromBase64Chars(base64PubKey, pubKeyBuffer.Span);

            //Try to encrypt the data
            return pbkBytesWritten ? TryEncrypt(pubKeyBuffer.Span[..(int)pbkBytesWritten], data, outputBuffer) : ERRNO.E_FAIL;
        }

        /// <summary>
        /// Tries to encrypt the specified data using the specified public key
        /// </summary>
        /// <param name="rawPubKey">The raw SKI public key</param>
        /// <param name="data">Data to encrypt</param>
        /// <param name="outputBuffer">The buffer to store encrypted data in</param>
        /// <returns>
        /// The number of encrypted bytes written to the output buffer,
        /// or false (0) if the operation failed, or if no credential is 
        /// specified.
        /// </returns>
        /// <exception cref="CryptographicException"></exception>
        public static ERRNO TryEncrypt(ReadOnlySpan<byte> rawPubKey, ReadOnlySpan<byte> data, Span<byte> outputBuffer)
        {
            if (rawPubKey.IsEmpty)
            {
                return false;
            }

            //Setup new empty rsa
            using RSA rsa = RSA.Create();

            //Import the public key
            rsa.ImportSubjectPublicKeyInfo(rawPubKey, out _);

            //Encrypt data with OaepSha256 as configured in the browser
            return rsa.TryEncrypt(data, outputBuffer, ClientEncryptonPadding, out int bytesWritten) ? bytesWritten : ERRNO.E_FAIL;
        }
    }
}
