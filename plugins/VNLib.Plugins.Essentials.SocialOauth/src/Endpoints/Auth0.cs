﻿/*
* Copyright (c) 2022 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.SocialOauth
* File: Auth0.cs 
*
* Auth0.cs is part of VNLib.Plugins.Essentials.SocialOauth which is part of the larger 
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
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;

using RestSharp;

using VNLib.Net.Rest.Client;
using VNLib.Hashing;
using VNLib.Hashing.IdentityUtility;
using VNLib.Utils.Logging;
using VNLib.Plugins.Essentials.Accounts;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Users;

namespace VNLib.Plugins.Essentials.SocialOauth.Endpoints
{

    [ConfigurationName("auth0")]
    internal sealed class Auth0 : SocialOauthBase
    {

        protected override OauthClientConfig Config { get; }


        private readonly Task<ReadOnlyJsonWebKey[]> Auth0VerificationJwk;

        public Auth0(PluginBase plugin, IReadOnlyDictionary<string, JsonElement> config) : base()
        {
            string keyUrl = config["key_url"].GetString() ?? throw new KeyNotFoundException("Missing Auth0 'key_url' from config");

            Uri keyUri = new(keyUrl);

            //Get certificate on background thread
            Auth0VerificationJwk = Task.Run(() => GetRsaCertificate(keyUri));

            Config = new("auth0", config)
            {
                Passwords = plugin.GetPasswords(),
                Users = plugin.GetUserManager(),
            };

            InitPathAndLog(Config.EndpointPath, plugin.Log);

            //Load secrets
            _ = plugin.DeferTask(async () =>
            {
                //Get id/secret
                Task<SecretResult?> secretTask = plugin.TryGetSecretAsync("auth0_client_secret");
                Task<SecretResult?> clientIdTask = plugin.TryGetSecretAsync("auth0_client_id");

                await Task.WhenAll(secretTask, clientIdTask);

                using SecretResult? secret = await secretTask;
                using SecretResult? clientId = await clientIdTask;

                Config.ClientID = clientId?.Result.ToString() ?? throw new KeyNotFoundException("Missing Auth0 client id from config or vault");
                Config.ClientSecret = secret?.Result.ToString() ?? throw new KeyNotFoundException("Missing the Auth0 client secret from config or vault");
               
            }, 100);
        }


        private async Task<ReadOnlyJsonWebKey[]> GetRsaCertificate(Uri certUri)
        {
            try
            {
                Log.Debug("Getting Auth0 signing keys");
                //Get key request
                RestRequest keyRequest = new(certUri, Method.Get);
                keyRequest.AddHeader("Accept", "application/json");

                //rent client from pool
                RestResponse response;
                
                using (ClientContract client = ClientPool.Lease())
                {
                    response = await client.Resource.ExecuteAsync(keyRequest);
                }

                response.ThrowIfError();

                //Get response as doc
                using JsonDocument doc = JsonDocument.Parse(response.RawBytes);

                //Create a new jwk from each key element in the response
                ReadOnlyJsonWebKey[] keys = doc.RootElement.GetProperty("keys")
                                            .EnumerateArray()
                                            .Select(static k => new ReadOnlyJsonWebKey(k))
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
         * Account data may be recovered from the identity token
         * and it happens after a call to GetLoginData so 
         * we do not need to re-verify the token
         */
        protected override Task<AccountData?> GetAccountDataAsync(IOAuthAccessState clientAccess, CancellationToken cancellationToken)
        {
            using JsonWebToken jwt = JsonWebToken.Parse(clientAccess.IdToken);

            //verify signature

            using JsonDocument userData = jwt.GetPayload();

            if (!userData.RootElement.GetProperty("email_verified").GetBoolean())
            {
                return Task.FromResult<AccountData?>(null);
            }

            string fullName = userData.RootElement.GetProperty("name").GetString() ?? " ";

            return Task.FromResult<AccountData?>(new AccountData()
            {
                EmailAddress = userData.RootElement.GetProperty("email").GetString(),
                First = fullName.Split(' ')[0],
                Last = fullName.Split(' ')[1],
            });
        }

        private static string GetUserIdFromPlatform(string userName)
        {
            /*
             * Auth0 uses the format "platoform|{user_id}" for the user id so it should match the 
             * external platofrm as github and discord endoints also
             */

            return ManagedHash.ComputeHash(userName, HashAlg.SHA1, HashEncodingMode.Hexadecimal);
        }

        
        private static readonly Task<UserLoginData?> EmptyLoginData = Task.FromResult<UserLoginData?>(null);

        protected override Task<UserLoginData?> GetLoginDataAsync(IOAuthAccessState clientAccess, CancellationToken cancellation)
        {
            using JsonWebToken jwt = JsonWebToken.Parse(clientAccess.IdToken);

            //Verify the token against the first signing key
            if (!jwt.VerifyFromJwk(Auth0VerificationJwk.Result[0]))
            {
                return EmptyLoginData;
            }
           
            using JsonDocument userData = jwt.GetPayload();

            int iat = userData.RootElement.GetProperty("iat").GetInt32();
            int exp = userData.RootElement.GetProperty("exp").GetInt32();

            string userId = userData.RootElement.GetProperty("sub").GetString() ?? throw new Exception("Missing sub in jwt");
            string audience = userData.RootElement.GetProperty("aud").GetString() ?? throw new Exception("Missing aud in jwt");
            string issuer = userData.RootElement.GetProperty("iss").GetString() ?? throw new Exception("Missing iss in jwt");

            if(exp < DateTimeOffset.UtcNow.ToUnixTimeSeconds())
            {
                //Expired
                return EmptyLoginData;
            }

            //Verify audience matches client id
            if (!Config.ClientID.Equals(audience, StringComparison.Ordinal))
            {
                //Invalid audience
                return EmptyLoginData;
            }

            return Task.FromResult<UserLoginData?>(new UserLoginData()
            {
                UserId = GetUserIdFromPlatform(userId)
            });
        }
    }
}
