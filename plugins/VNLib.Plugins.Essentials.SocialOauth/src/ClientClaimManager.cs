/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.SocialOauth
* File: ClientClaimManager.cs 
*
* ClientClaimManager.cs is part of VNLib.Plugins.Essentials.SocialOauth which is part of the larger 
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
using System.Diagnostics.CodeAnalysis;

using VNLib.Hashing;
using VNLib.Hashing.IdentityUtility;
using VNLib.Utils;
using VNLib.Utils.Memory;
using VNLib.Utils.Extensions;
using VNLib.Plugins.Essentials.Accounts;
using VNLib.Plugins.Essentials.Extensions;

namespace VNLib.Plugins.Essentials.SocialOauth
{
    internal sealed record class ClientClaimManager(ICookieController Cookies)
    {
        const string SESSION_SIG_KEY_NAME = "soa.sig";
        const int SIGNING_KEY_SIZE = 32;

        public bool VerifyAndGetClaim(HttpEntity entity, [NotNullWhen(true)] out LoginClaim? claim)
        {
            claim = null;

            string? cookieValue = Cookies.GetCookie(entity);

            //Try to get the cookie
            if (cookieValue == null)
            {
                return false;
            }

            //Recover the signing key from the user's session
            string sigKey = entity.Session[SESSION_SIG_KEY_NAME];
            Span<byte> key = stackalloc byte[SIGNING_KEY_SIZE + 16];

            ERRNO keySize = VnEncoding.Base64UrlDecode(sigKey, key);

            if (keySize < 1)
            {
                return false;
            }

            try
            {
                //Try to parse the jwt
                using JsonWebToken jwt = JsonWebToken.Parse(cookieValue);

                //Verify the jwt
                if (!jwt.Verify(key[..(int)keySize], HashAlg.SHA256))
                {
                    return false;
                }

                //Recover the clam from the jwt
                claim = jwt.GetPayload<LoginClaim>();

                //Verify the expiration time
                return claim.ExpirationSeconds > entity.RequestedTimeUtc.ToUnixTimeSeconds();
            }
            catch (FormatException)
            {
                //JWT was corrupted and could not be parsed
                return false;
            }
            finally
            {
                MemoryUtil.InitializeBlock(key);
            }
        }

        public void ClearClaimData(HttpEntity entity)
        {
            //Remove the upgrade cookie
            Cookies.ExpireCookie(entity, false);

            //Clear the signing key from the session
            entity.Session[SESSION_SIG_KEY_NAME] = null!;
        }

        public void SignAndSetCookie(HttpEntity entity, LoginClaim claim)
        {
            //Setup Jwt
            using JsonWebToken jwt = new();

            //Write claim body, we dont need a header
            jwt.WritePayload(claim, Statics.SR_OPTIONS);

            //Generate signing key
            byte[] sigKey = RandomHash.GetRandomBytes(SIGNING_KEY_SIZE);

            //Sign the jwt
            jwt.Sign(sigKey, HashAlg.SHA256);

            Cookies.SetCookie(entity, jwt.Compile());

            //Encode and store the signing key in the clien't session
            entity.Session[SESSION_SIG_KEY_NAME] = VnEncoding.ToBase64UrlSafeString(sigKey, false);

            //Clear the signing key
            MemoryUtil.InitializeBlock(sigKey.AsSpan());
        }
    }
}
