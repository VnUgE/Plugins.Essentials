/*
* Copyright (c) 2022 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.SocialOauth
* File: GitHubOauth.cs 
*
* GitHubOauth.cs is part of VNLib.Plugins.Essentials.SocialOauth which is part of the larger 
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

#nullable enable

namespace VNLib.Plugins.Essentials.SocialOauth.Endpoints
{
    [ConfigurationName("github")]
    internal sealed partial class GitHubOauth : SocialOauthBase
    {
        private const string GITHUB_V3_ACCEPT = "application/vnd.github.v3+json";

        private readonly string UserEmailUrl;

        protected override OauthClientConfig Config { get; }

        public GitHubOauth(PluginBase plugin, IReadOnlyDictionary<string, JsonElement> config) : base()
        {
            //Get id/secret
            Task<string?> secret = plugin.TryGetSecretAsync("github_client_secret");
            Task<string?> clientId = plugin.TryGetSecretAsync("github_client_id");

            //Wait sync
            Task.WaitAll(secret, clientId);

            Config = new(configName: "github", config)
            {
                //get gh client secret and id
                ClientID = clientId.Result ?? throw new KeyNotFoundException("Missing Github client id from config or vault"),
                ClientSecret = secret.Result ?? throw new KeyNotFoundException("Missing Github client secret from config or vault"),

                Passwords = plugin.GetPasswords(),
                Users = plugin.GetUserManager(),
            };


            UserEmailUrl = config["user_email_url"].GetString() ?? throw new KeyNotFoundException("Missing required key 'user_email_url' for github configuration");

            InitPathAndLog(Config.EndpointPath, plugin.Log);
        }

        protected override void StaticClientPoolInitializer(RestClient client)
        {
            client.UseSerializer<RestSharp.Serializers.Json.SystemTextJsonSerializer>();
            //add accept types of normal json and github json
            client.AcceptedContentTypes = new string[2] { "application/json", GITHUB_V3_ACCEPT };
        }

        /*
         * Matches the json result from the 
         */
        private sealed class GithubProfile
        {
            [JsonPropertyName("login")]
            public string? Username { get; set; }
            [JsonPropertyName("id")]
            public int ID { get; set; }
            [JsonPropertyName("node_id")]
            public string? NodeID { get; set; }
            [JsonPropertyName("avatar_url")]
            public string? AvatarUrl { get; set; }
            [JsonPropertyName("url")]
            public string? ProfileUrl { get; set; }
            [JsonPropertyName("type")]
            public string? Type { get; set; }
            [JsonPropertyName("name")]
            public string? FullName { get; set; }
            [JsonPropertyName("company")]
            public string? Company { get; set; }
        }
        /*
         * Matches the required data from the github email endpoint
         */
        private sealed class EmailContainer
        {
            [JsonPropertyName("email")]
            public string? Email { get; set; }
            [JsonPropertyName("primary")]
            public bool Primary { get; set; }
            [JsonPropertyName("verified")]
            public bool Verified { get; set; }
        }

        private static string GetUserIdFromPlatform(int userId)
        {
            return ManagedHash.ComputeHash($"github|{userId}", HashAlg.SHA1, HashEncodingMode.Hexadecimal);
        }

        protected override async Task<UserLoginData?> GetLoginDataAsync(IOAuthAccessState accessToken, CancellationToken cancellationToken)
        {
            //Get the user's email address's
            RestRequest request = new(Config.UserDataUrl, Method.Get);

            //Add authorization token
            request.AddHeader("Authorization", $"{accessToken.Type} {accessToken.Token}");

            //Get new client from pool
            using ClientContract client = ClientPool.Lease();

            //Exec the get for the profile
            RestResponse<GithubProfile> profResponse =  await client.Resource.ExecuteAsync<GithubProfile>(request, cancellationToken);

            if (!profResponse.IsSuccessful || profResponse.Data == null || profResponse.Data.ID < 100)
            {
                Log.Debug("Github login data attempt responded with status code {code}", profResponse.StatusCode);
                return null;
            }

            //Return login data
            return new()
            {
                //User-id is just the SHA 1 
                UserId = GetUserIdFromPlatform(profResponse.Data.ID)
            };
        }

        protected override async Task<AccountData?> GetAccountDataAsync(IOAuthAccessState accessToken, CancellationToken cancellationToken = default)
        {
            AccountData? accountData = null;
            //Get the user's email address's
            RestRequest request = new(UserEmailUrl, Method.Get);
            //Add authorization token
            request.AddHeader("Authorization", $"{accessToken.Type} {accessToken.Token}");

            using ClientContract client = ClientPool.Lease();

            //get user's emails
            RestResponse<EmailContainer[]> getEmailResponse = await client.Resource.ExecuteAsync<EmailContainer[]>(request, cancellationToken: cancellationToken);
            //Check status
            if (getEmailResponse.IsSuccessful && getEmailResponse.Data != null)
            {
                //Filter emails addresses 
                foreach (EmailContainer email in getEmailResponse.Data)
                {
                    //Capture the first primary email address and make sure its verified
                    if (email.Primary && email.Verified)
                    {
                        accountData = new()
                        {
                            //store email on current profile
                            EmailAddress = email.Email
                        };
                        goto Continue;
                    }
                }
                //No primary email found
                return null;
            }
            else
            {
                Log.Debug("Github account data request failed but GH responded with status code {code}", getEmailResponse.StatusCode);
                return null;
            }
        Continue:
            //We need to get the user's profile in order to create a new account
            request = new(Config.UserDataUrl, Method.Get);
            //Add authorization token
            request.AddHeader("Authorization", $"{accessToken.Type} {accessToken.Token}");
            //Exec the get for the profile
            RestResponse<GithubProfile> profResponse =  await client.Resource.ExecuteAsync<GithubProfile>(request, cancellationToken);
            if (!profResponse.IsSuccessful || profResponse.Data == null)
            {
                Log.Debug("Github account data request failed but GH responded with status code {code}", profResponse.StatusCode);
                return null;
            }

            //Get the user's name from gh profile
            string[] names = profResponse.Data.FullName!.Split(" ", StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            //setup the user's profile data
            accountData.First = names.Length > 0 ? names[0] : string.Empty;
            accountData.Last = names.Length > 1 ? names[1] : string.Empty;
            return accountData;
        }


    }
}