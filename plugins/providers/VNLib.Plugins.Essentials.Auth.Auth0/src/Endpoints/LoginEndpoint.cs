/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Auth.Auth0
* File: LoginEndpoint.cs 
*
* LoginEndpoint.cs is part of VNLib.Plugins.Essentials.Auth.Auth0 which is 
* part of the larger VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Auth.Auth0 is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Auth.Auth0 is distributed in the hope that it will be useful,
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
using System.Threading;
using System.Threading.Tasks;

using RestSharp;

using VNLib.Hashing;
using VNLib.Hashing.IdentityUtility;
using VNLib.Utils.Logging;
using VNLib.Plugins.Essentials.Accounts;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Net.Rest.Client.Construction;
using VNLib.Plugins.Essentials.Auth.Social;

/*
 * Provides specialized login for Auth0 identity managment system. Auth0 apis use JWT tokens
 * and JWK signing keys. Keys are downloaded when the plugin is first loaded and cached for
 * the lifetime of the plugin. The keys are used to verify the JWT token and extract the user
 */

namespace VNLib.Plugins.Essentials.Auth.Auth0.Endpoints
{

    [ConfigurationName(Auth0Portal.ConfigKey)]
    internal sealed class LoginEndpoint : SocialOauthBase
    {
        private readonly IAsyncLazy<ReadOnlyJsonWebKey[]> Auth0VerificationJwk;
        private readonly bool VerifyEmail;

        public LoginEndpoint(PluginBase plugin, IConfigScope config) : base(plugin, config)
        {
            string keyUrl = config.GetRequiredProperty("key_url", p => p.GetString()!);

            //Define the key endpoint
            SiteAdapter.DefineSingleEndpoint()
                .WithEndpoint<GetKeyRequest>()
                .WithUrl(keyUrl)
                .WithMethod(Method.Get)
                .WithHeader("Accept", "application/json")
                .OnResponse((r, res) => res.ThrowIfError());

            //Check for email verification
            VerifyEmail = config.TryGetValue("verified_email", out JsonElement el) && el.GetBoolean();

            //Get certificate on background thread
            Auth0VerificationJwk = Task.Run(GetRsaCertificate).AsLazy();
        }

        private async Task<ReadOnlyJsonWebKey[]> GetRsaCertificate()
        {
            try
            {
                Log.Debug("Getting Auth0 signing keys");

                //rent client from pool
                RestResponse response = await SiteAdapter.ExecuteAsync(new GetKeyRequest());

                //Get response as doc
                using JsonDocument doc = JsonDocument.Parse(response.RawBytes);

                //Create a new jwk from each key element in the response
                ReadOnlyJsonWebKey[] keys = doc.RootElement.GetProperty("keys")
                                            .EnumerateArray()
                                            .Select(static k => new ReadOnlyJsonWebKey(in k))
                                            .ToArray();

                Log.Debug("Found {count} Auth0 signing keys", keys.Length);

                return keys;
            }
            catch (Exception e)
            {
                Log.Error(e, "Failed to get Auth0 signing keys");
                throw;
            }
        }

        /*
         * Auth0 uses the format "platoform|{user_id}" for the user id so it should match the 
         * external platofrm as github and discord endoints also
         */

        private static string GetUserIdFromPlatform(string userName)
        {
            return ManagedHash.ComputeHash(userName, HashAlg.SHA1, HashEncodingMode.Hexadecimal);
        }


        private static readonly Task<UserLoginData?> EmptyLoginData = Task.FromResult<UserLoginData?>(null);
        private static readonly Task<AccountData?> EmptyUserData = Task.FromResult<AccountData?>(null);

        ///<inheritdoc/>
        protected override Task<UserLoginData?> GetLoginDataAsync(IOAuthAccessState clientAccess, CancellationToken cancellation)
        {
            //recover the identity token
            using JsonWebToken jwt = JsonWebToken.Parse(clientAccess.IdToken);

            //Verify the token against the first signing key
            if (!jwt.VerifyFromJwk(Auth0VerificationJwk.Value[0]))
            {
                return EmptyLoginData;
            }

            using JsonDocument userData = jwt.GetPayload();

            int iat = userData.RootElement.GetProperty("iat").GetInt32();
            int exp = userData.RootElement.GetProperty("exp").GetInt32();

            string userId = userData.RootElement.GetProperty("sub").GetString() ?? throw new Exception("Missing sub in jwt");
            string audience = userData.RootElement.GetProperty("aud").GetString() ?? throw new Exception("Missing aud in jwt");
            string issuer = userData.RootElement.GetProperty("iss").GetString() ?? throw new Exception("Missing iss in jwt");

            if (exp < DateTimeOffset.UtcNow.ToUnixTimeSeconds())
            {
                //Expired
                return EmptyLoginData;
            }

            //Verify audience matches client id
            if (!Config.ClientID.Value.Equals(audience, StringComparison.Ordinal))
            {
                //Invalid audience
                return EmptyLoginData;
            }

            return Task.FromResult<UserLoginData?>(new UserLoginData()
            {
                UserId = GetUserIdFromPlatform(userId)
            });
        }

        /*
         * Account data may be recovered from the identity token
         * and it happens after a call to GetLoginData so 
         * we do not need to re-verify the token
         */
        ///<inheritdoc/>
        protected override Task<AccountData?> GetAccountDataAsync(IOAuthAccessState clientAccess, CancellationToken cancellationToken)
        {
            //Parse token again to get the user data
            using JsonWebToken jwt = JsonWebToken.Parse(clientAccess.IdToken);

            using JsonDocument userData = jwt.GetPayload();

            //Confirm email is verified
            if (!userData.RootElement.GetProperty("email_verified").GetBoolean() && VerifyEmail)
            {
                return EmptyUserData;
            }

            string fullName = userData.RootElement.GetProperty("name").GetString() ?? " ";

            return Task.FromResult<AccountData?>(new AccountData()
            {
                EmailAddress = userData.RootElement.GetProperty("email").GetString(),
                First = fullName.Split(' ').FirstOrDefault(),
                Last = fullName.Split(' ').LastOrDefault(),
            });
        }

        private sealed record class GetKeyRequest()
        { }
    }
}
