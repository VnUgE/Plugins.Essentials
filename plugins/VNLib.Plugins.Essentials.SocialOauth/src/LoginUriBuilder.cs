/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.SocialOauth
* File: LoginUriBuilder.cs 
*
* LoginUriBuilder.cs is part of VNLib.Plugins.Essentials.SocialOauth which is part of the larger 
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
using System.Text;
using System.Runtime.InteropServices;

using VNLib.Utils;
using VNLib.Utils.Memory;
using VNLib.Utils.Extensions;
using VNLib.Plugins.Essentials.Accounts;

namespace VNLib.Plugins.Essentials.SocialOauth
{
    /*
     * Construct the client's redirect url based on their login claim, which contains
     * a public key which can be used to encrypt the url so that only the client 
     * private-key holder can decrypt the url and redirect themselves to the 
     * target OAuth website. 
     * 
     * The result is an encrypted nonce that should guard against replay attacks and MITM
     */

    internal sealed record class LoginUriBuilder(OauthClientConfig Config)
    {
        private string? redirectUrl;
        private string? nonce;
        private Encoding _encoding = Encoding.UTF8;

        public LoginUriBuilder WithUrl(ReadOnlySpan<char> scheme, ReadOnlySpan<char> authority, ReadOnlySpan<char> path)
        {
            //Alloc stack buffer for url
            Span<char> buffer = stackalloc char[1024];

            //buffer writer for easier syntax
            ForwardOnlyWriter<char> writer = new(buffer);
            //first build the redirect url to re-encode it
            writer.Append(scheme);
            writer.Append("://");
            //Create redirect url (current page, default action is to authorize the client)
            writer.Append(authority);
            writer.Append(path);
            //url encode the redirect path and save it for later
            redirectUrl = Uri.EscapeDataString(writer.ToString());

            return this;
        }

        public LoginUriBuilder WithEncoding(Encoding encoding)
        {
            _encoding = encoding;
            return this;
        }

        public LoginUriBuilder WithNonce(string base32Nonce)
        {
            nonce = base32Nonce;
            return this;
        }

        public string Encrypt(HttpEntity client, IClientSecInfo secInfo)
        {
            //Alloc buffer and split it into binary and char buffers
            using UnsafeMemoryHandle<byte> buffer = MemoryUtil.UnsafeAllocNearestPage(8000);

            Span<byte> binBuffer = buffer.Span[2048..];
            Span<char> charBuffer = MemoryMarshal.Cast<byte, char>(buffer.Span[..2048]);


            /*
             * Build the character uri so we can encode it to binary, 
             * encrypt it and return it to the client
             */

            ForwardOnlyWriter<char> writer = new(charBuffer);

            //Append the config redirect path
            writer.Append(Config.AccessCodeUrl.OriginalString);
            //begin query arguments
            writer.Append("&client_id=");
            writer.Append(Config.ClientID.Value);
            //add the redirect url
            writer.Append("&redirect_uri=");
            writer.Append(redirectUrl);
            //Append the state parameter
            writer.Append("&state=");
            writer.Append(nonce);

            //Collect the written character data
            ReadOnlySpan<char> url = writer.AsSpan();

            //Separate bin buffers for encryption and encoding
            Span<byte> encryptionBuffer = binBuffer[1024..];
            Span<byte> encodingBuffer = binBuffer[..1024];

            //Encode the url to binary
            int byteCount = _encoding.GetBytes(url, encodingBuffer);

            //Encrypt the binary data
            ERRNO count = client.TryEncryptClientData(secInfo, encodingBuffer[..byteCount], encryptionBuffer);

            //base64 encode the encrypted
            return Convert.ToBase64String(encryptionBuffer[0..(int)count]);
        }
    }
}
