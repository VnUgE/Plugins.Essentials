/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: LoginEndpoint.cs 
*
* LoginEndpoint.cs is part of VNLib.Plugins.Essentials.Accounts which is part of the larger 
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
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

using VNLib.Plugins.Essentials.Users;
using VNLib.Hashing.IdentityUtility;

using VNLib.Utils;
using VNLib.Utils.Memory;
using VNLib.Hashing;
using VNLib.Utils.Extensions;

namespace VNLib.Plugins.Essentials.Accounts.MFA.Fido
{
    internal sealed class FidoMfaProcessor(FidoConfig conf) : IMfaProcessor
    {
        const string JwtClaimKey = "fido";

        ///<inheritdoc/>
        public MFAType Type => MFAType.TOTP;

        ///<inheritdoc/>
        public void ExtendUpgradePayload(in JwtPayload message, IUser user)
        {
            FidoDeviceCredential[]? devices = user.FidoGetAllCredentials();

            if(devices == null || devices.Length == 0)
            {
                return;
            }

            using UnsafeMemoryHandle<byte> challBuffer = MemoryUtil.UnsafeAlloc(conf.ChallangeSize, true);

            RandomHash.GetRandomBytes(challBuffer.Span);

            message.AddClaim(
                claim: JwtClaimKey, 
                value: GetChallengeData(challBuffer.Span, devices)
            );
        }

        ///<inheritdoc/>
        public bool MethodEnabledForUser(IUser user) => user.FidoEnabled();

        ///<inheritdoc/>
        public bool VerifyResponse(MfaChallenge upgrade, IUser user, JsonDocument result)
        {
            FidoUpgradeResponse? fidoResponse = result.RootElement.GetProperty("fido")
                .Deserialize<FidoUpgradeResponse>();

            if (fidoResponse is null)
            {
                return false;
            }



            return false;
        }

        private ERRNO RecoverFidoChallenge(JsonDocument chalUpgrade, Span<byte> outBuffer)
        {
            /*
             * When this function is called it must be assumed that the mfa token signature
             * was verified so it doesn't need to be checked again. 
             * 
             * The only data we need to recover from the upgrade is the fido challenge data.
             * to verify it's signature.
             */

            string? chalJwtData = chalUpgrade.RootElement.GetPropString("mfa");
            if (string.IsNullOrWhiteSpace(chalJwtData))
            {
                return 0;
            }

            using JsonWebToken jwt = JsonWebToken.Parse(chalJwtData);

            using JsonDocument chalDoc = jwt.GetPayload();

            string challenge = chalDoc.RootElement.GetProperty(JwtClaimKey)
                .GetProperty("challenge")
                .GetString()!;

            return VnEncoding.Base64UrlDecode(challenge, outBuffer);
        }

        private FidoDevUpgradeJson GetChallengeData(ReadOnlySpan<byte> challenge, FidoDeviceCredential[] devices)
        {
            return new FidoDevUpgradeJson
            {
                Base64UrlChallange = VnEncoding.Base64UrlEncode(challenge, includePadding: false),
              
                Timeout = conf.Timeout,
                
                Credentials = devices.Select(p => new CredentialInfoJson
                {
                    Base64UrlId = p.Base64UrlId,
                    Transports = conf.Transports,
                    Type = "public-key"
                }).ToArray(),
            };
        }

        sealed class FidoDevUpgradeJson
        {
            [JsonPropertyName("challenge")]
            public string Base64UrlChallange { get; set; } = string.Empty;

            [JsonPropertyName("allowCredentials")]
            public CredentialInfoJson[] Credentials { get; set; } = Array.Empty<CredentialInfoJson>();

            [JsonPropertyName("timeout")]
            public int Timeout { get; set; }
        }

        sealed class CredentialInfoJson
        {
            [JsonPropertyName("id")]
            public string Base64UrlId { get; set; } = string.Empty;

            [JsonPropertyName("type")]
            public string Type { get; set; } = "public-key";

            [JsonPropertyName("transports")]
            public string[] Transports { get; set; } = Array.Empty<string>();
        }
    }

    internal sealed class FidoUpgradeResponse
    {
        [JsonPropertyName("id")]
        public string Base64UrlId { get; set; } = string.Empty;

        [JsonPropertyName("authenticatorAttachment")]
        public string? Attachment { get; set; }

        [JsonPropertyName("response")]
        public FidoAuthenticatorAssertionResponse? Response { get; set; }
    }

    internal sealed class FidoAuthenticatorAssertionResponse
    {
        [JsonPropertyName("authenticatorData")]
        public string Base64UrlAuthData { get; set; } = string.Empty;

        [JsonPropertyName("clientDataJSON")]
        public string Base64UrlClientData { get; set; } = string.Empty;

        [JsonPropertyName("signature")]
        public string Base64UrlSignature { get; set; } = string.Empty;

        [JsonPropertyName("userHandle")]
        public string? Base64UrlUserHandle { get; set; }
    }
}