/*
* Copyright (c) 2022 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.SocialOauth
* File: DiscordOauth.cs 
*
* DiscordOauth.cs is part of VNLib.Plugins.Essentials.SocialOauth which is part of the larger 
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
using System.Threading;
using System.Text.Json;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text.Json.Serialization;

using RestSharp;

using VNLib.Hashing;
using VNLib.Utils.Logging;
using VNLib.Net.Rest.Client;
using VNLib.Plugins.Essentials.Accounts;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Users;

namespace VNLib.Plugins.Essentials.SocialOauth.Endpoints
{
    [ConfigurationName("discord")]
    internal sealed class DiscordOauth : SocialOauthBase
    {
        protected override OauthClientConfig Config { get; }

        public DiscordOauth(PluginBase plugin, IReadOnlyDictionary<string, JsonElement> config) : base()
        {
            Config = new("discord", config)
            {
                Passwords = plugin.GetPasswords(),
                Users = plugin.GetUserManager(),
            };

            InitPathAndLog(Config.EndpointPath, plugin.Log);

            //Load secrets
            _ = plugin.DeferTask(async () =>
            {
                //Get id/secret
                Task<SecretResult?> clientIdTask = plugin.TryGetSecretAsync("discord_client_id");
                Task<SecretResult?> secretTask = plugin.TryGetSecretAsync("discord_client_secret");

                await Task.WhenAll(secretTask, clientIdTask);

                using SecretResult? secret = await secretTask;
                using SecretResult? clientId = await clientIdTask;

                Config.ClientID = clientId?.Result.ToString() ?? throw new KeyNotFoundException("Missing Discord client id from config or vault");
                Config.ClientSecret = secret?.Result.ToString() ?? throw new KeyNotFoundException("Missing the Discord client secret from config or vault");

            }, 100);
        }

        
        private static string GetUserIdFromPlatform(string userName)
        {
            return ManagedHash.ComputeHash($"discord|{userName}", HashAlg.SHA1, HashEncodingMode.Hexadecimal);
        }


        /*
         * Matches the profile endpoint (@me) json object 
         */
        private sealed class UserProfile
        {
            [JsonPropertyName("username")]
            public string? Username { get; set; }
            [JsonPropertyName("id")]
            public string? UserID { get; set; }
            [JsonPropertyName("url")]
            public string? ProfileUrl { get; set; }
            [JsonPropertyName("verified")]
            public bool Verified { get; set; }
            [JsonPropertyName("email")]
            public string? EmailAddress { get; set; }
        }


        protected override async Task<AccountData?> GetAccountDataAsync(IOAuthAccessState accessToken, CancellationToken cancellationToken)
        {
            //Get the user's email address's
            RestRequest request = new(Config.UserDataUrl);
            //Add authorization token
            request.AddHeader("Authorization", $"{accessToken.Type} {accessToken.Token}");
            //Get client from pool
            using ClientContract client = ClientPool.Lease();
            //get user's profile data
            RestResponse<UserProfile> getProfileResponse = await client.Resource.ExecuteAsync<UserProfile>(request, cancellationToken: cancellationToken);
            //Check response
            if (!getProfileResponse.IsSuccessful || getProfileResponse.Data == null)
            {
                Log.Debug("Discord user request responded with code {code}:{data}", getProfileResponse.StatusCode, getProfileResponse.Content);
                return null;
            }
            UserProfile discordProfile = getProfileResponse.Data;
            //Make sure the user's account is verified
            if (!discordProfile.Verified)
            {
                return null;
            }
            return new()
            {
                EmailAddress = discordProfile.EmailAddress,
                First = discordProfile.Username,
            };
        }

        protected override async Task<UserLoginData?> GetLoginDataAsync(IOAuthAccessState accessToken, CancellationToken cancellationToken)
        {
            //Get the user's email address's
            RestRequest request = new(Config.UserDataUrl);
            //Add authorization token
            request.AddHeader("Authorization", $"{accessToken.Type} {accessToken.Token}");
            //Get client from pool
            using ClientContract client = ClientPool.Lease();
            //get user's profile data
            RestResponse<UserProfile> getProfileResponse = await client.Resource.ExecuteAsync<UserProfile>(request, cancellationToken: cancellationToken);
            //Check response
            if (!getProfileResponse.IsSuccessful || getProfileResponse.Data?.UserID == null)
            {
                Log.Debug("Discord user request responded with code {code}:{data}", getProfileResponse.StatusCode, getProfileResponse.Content);
                return null;
            }

            UserProfile discordProfile = getProfileResponse.Data;

            return new()
            {
                //Get unique user-id from the discord profile and sha1 hex hash to store in db
                UserId = GetUserIdFromPlatform(discordProfile.UserID)
            };
        }
    }
}