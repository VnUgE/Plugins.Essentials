/*
* Copyright (c) 2025 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Auth.Social
* File: SocialAuthStateManager.cs 
*
* SocialAuthStateManager.cs is part of VNLib.Plugins.Essentials.Auth.Social which is 
* part of the larger VNLib collection of libraries and utilities.
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

using System;
using System.Text.Json;

using RestSharp;

using VNLib.Utils;
using VNLib.Utils.Memory;
using VNLib.Hashing;
using VNLib.Hashing.IdentityUtility;
using VNLib.Plugins.Essentials.Accounts;

namespace VNLib.Plugins.Essentials.Auth.Social.Controllers
{
    internal sealed class SocialAuthStateManager
    {
        private const HashAlg SigAlg = HashAlg.SHA256;

        private readonly SocialOauthConfigJson _config;

        internal SocialAuthStateManager(SocialOauthConfigJson config)
            => _config = config;

        /// <summary>
        /// Clears all client upgrade data from the session
        /// </summary>
        /// <param name="entity"></param>
        internal void ClearUpgrade(HttpEntity entity)
        {
            SetSigningKey(entity, null!);
        }

        internal string CreateClientUpgrade(HttpEntity entity, string methodId, IClientSecInfo secInfo, object? userData)
        {
            long expires = entity.RequestedTimeUtc
                    .AddSeconds(_config.UpgradeTimeoutSec)
                    .ToUnixTimeSeconds();

            using JsonWebToken jwt = new();

            jwt.InitPayloadClaim(initCapacity: 8)
                .AddClaim("ud", userData)
                .AddClaim("exp", expires)
                .AddClaim("sub", secInfo)
                .AddClaim("method", methodId)
                .AddClaim("iss", entity.Server.RequestUri.GetLeftPart(UriPartial.Authority))
                .AddClaim("aud", entity.Server.RequestUri.GetLeftPart(UriPartial.Authority))
                .AddClaim("iat", entity.RequestedTimeUtc.ToUnixTimeSeconds())
                .AddClaim("org", entity.Server.Origin)
                .CommitClaims();

            SignAndSetKey(entity, jwt);
            return jwt.ToString();
        }

        internal T GetSecInfo<T>(JsonDocument upgradeDoc) where T: IClientSecInfo
        {
            return upgradeDoc.RootElement
                .GetProperty("sub")
                .Deserialize<T>()!;
        }

        internal JsonElement GetUserDataElement(JsonDocument upgradeDoc)
        {
            return upgradeDoc.RootElement.GetProperty("ud");
        }

        internal string GetMethodId(JsonDocument upgradeDoc)
        {
            return upgradeDoc.RootElement
                .GetProperty("method")
                .GetString()!;
        }

        internal bool IsUpgradeValid(HttpEntity entity, JsonDocument doc)
        {

            long exp = doc.RootElement.GetProperty("exp").GetInt64();
            string? issuer = doc.RootElement.GetProperty("iss").GetString();
            string? audience = doc.RootElement.GetProperty("aud").GetString();
            string? origin = doc.RootElement.GetProperty("org").GetString();

            //Check expiration time
            if (exp < entity.RequestedTimeUtc.ToUnixTimeSeconds())
            {
                return false;
            }

            string currentAuthority = entity.Server.RequestUri.GetLeftPart(UriPartial.Authority);

            if (
                !string.Equals(currentAuthority, issuer, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(currentAuthority, audience, StringComparison.OrdinalIgnoreCase)
                )
            {
                return false;
            }

            //Only check origin if the admin enforced it
            if (!_config.StrictOriginCheck)
            {
                return true;
            }

            string? currentOrigin = entity.Server.Origin?.ToString();
            return string.Equals(origin, currentOrigin, StringComparison.OrdinalIgnoreCase);
        }

        internal bool IsUpgradeSignatureValid(HttpEntity entity, JsonWebToken token)
        {
            ReadOnlySpan<char> signingKey = GetSigningKey(entity);
            if (signingKey.IsEmpty)
            {
                return false;
            }

            //Decode the signing key back into a binary
            using UnsafeMemoryHandle<byte> keyBuffer = MemoryUtil.UnsafeAlloc(signingKey.Length + 6);

            ERRNO byteCount = VnEncoding.Base64UrlDecode(signingKey, keyBuffer.Span);

            //Key must be decoded and verified
            return byteCount > 0 && token.Verify(keyBuffer.AsSpan(start: 0, byteCount), SigAlg);
        }

        private void SignAndSetKey(HttpEntity entity, JsonWebToken jwt)
        {
            using UnsafeMemoryHandle<byte> secKey = MemoryUtil.UnsafeAlloc(_config.SignatureKeySize);
            RandomHash.GetRandomBytes(secKey.Span);

            //Sign the JWT with the key
            jwt.Sign(secKey.Span, SigAlg);

            //Store the signing key in the user's session
            string signingKey = VnEncoding.Base64UrlEncode(secKey.Span, includePadding: false);
            SetSigningKey(entity, signingKey);

            //Zero out the key memory after signed
            MemoryUtil.InitializeBlock(ref secKey.GetReference(), secKey.IntLength);
        }

        private static string GetSigningKey(HttpEntity entity)
            => entity.Session["social.sig"];

        private static void SetSigningKey(HttpEntity entity, string key)
            => entity.Session["social.sig"] = key;

        public void SetAuthenticatedMethod(HttpEntity entity, string methodId)
            => entity.Session["social.method"] = methodId;

        public string? GetAuthenticatedMethod(HttpEntity entity)
            => entity.Session["social.method"];
    }
}
