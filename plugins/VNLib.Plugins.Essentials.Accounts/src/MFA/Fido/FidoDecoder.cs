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
using System.Security.Cryptography;


using VNLib.Utils;
using VNLib.Utils.Memory;
using VNLib.Plugins.Essentials.Accounts.MFA.Fido.JsonTypes;

namespace VNLib.Plugins.Essentials.Accounts.MFA.Fido
{
    internal static class FidoDecoder
    {

        /// <summary>
        /// Attemts to validate the response from the Fido authenticator by verifying the 
        /// attestation data signature
        /// </summary>
        /// <param name="response">The authentication response object</param>
        /// <param name="credential">The device to assign fields to</param>
        /// <returns>A value that indicates if the response data is valid and verified</returns>
        public static bool ValidateResponse(FidoAuthenticatorResponse response, out FidoDeviceCredential credential)
        {
            credential = new();

            //Make sure the response has a public key and a valid algorithm
            if (
                !response.CoseAlgorithmNumber.HasValue
                || string.IsNullOrWhiteSpace(response.Base64PublicKey)
                || string.IsNullOrWhiteSpace(response.Base64AuthenticatorData)
            )
            {
                return false;
            }

            /*
             * The public key is a bit more complicated to extract, so I'm going to use the 
             * one provided by the browser during the request. If the signature matches with
             * the public key sent, then we know the key and data is valid. 
             */

            credential.Name           = response.DeviceName ?? string.Empty;
            credential.CoseAlgId      = response.CoseAlgorithmNumber!.Value;
            credential.Base64DeviceId = response.DeviceId;

            //Try to get the ecdsa object which will be used to verify attestation data
            using ECDsa? sigAlg = GetSigningAlgForKey(response.Base64PublicKey, credential.CoseAlgId);

            if (sigAlg is null)
            {
                return false;
            }

            //Export the key parameters to get the x and y coordinates
            ECParameters keyParams = sigAlg.ExportParameters(includePrivateParameters: false);

            if (keyParams.Q.X?.Length != CoseEncodings.GetCoordSizeForAlg(credential.CoseAlgId))
            {
                return false;
            }

            //Assign key coordinates to the credential object
            credential.Base64XCoord = VnEncoding.Base64UrlEncode(keyParams.Q.X, includePadding: false);
            credential.Base64YCoord = VnEncoding.Base64UrlEncode(keyParams.Q.Y, includePadding: false);

            return true;
        }

        private static ECDsa? GetSigningAlgForKey(string spki, int algId)
        {
            using UnsafeMemoryHandle<byte> pubKeyBuffer = MemoryUtil.UnsafeAlloc<byte>(spki.Length + 16, zero: true);

            //Recover the base64url public key into it's spki binary format
            ERRNO pubkeySize = VnEncoding.Base64UrlDecode(spki, pubKeyBuffer.Span);
            ReadOnlySpan<byte> spkiPubKey = pubKeyBuffer.AsSpan(start: 0, pubkeySize);

            if (spkiPubKey.IsEmpty)
            {
                return null;
            }

            //Create the alg from the curve code
            ECDsa alg = ECDsa.Create(
                CoseEncodings.GetECCurveFromCode(algId)
            );

            try
            {
                //Read the public key data into the algorithm object
                alg.ImportSubjectPublicKeyInfo(spkiPubKey, out _);
                return alg;
            }
            catch
            {
                alg.Dispose();
                throw;
            }
        }
    }
}
