/*
* Copyright (c) 2023 Vaughn Nugent
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
using System.Threading;
using System.Text.Json;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text.Json.Serialization;

using RestSharp;

using VNLib.Hashing;
using VNLib.Utils.Logging;
using VNLib.Plugins.Essentials.Accounts;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Net.Rest.Client.Construction;


namespace VNLib.Plugins.Essentials.SocialOauth.Endpoints
{
    [ConfigurationName("github")]
    internal sealed partial class GitHubOauth : SocialOauthBase
    {
        private const string GITHUB_V3_ACCEPT = "application/vnd.github.v3+json";

        private readonly string UserEmailUrl;
        

        public GitHubOauth(PluginBase plugin, IConfigScope config) : base(plugin, config)
        {            
            UserEmailUrl = config["user_email_url"].GetString() ?? throw new KeyNotFoundException("Missing required key 'user_email_url' for github configuration");

            //Define profile endpoint, gets users required profile information
            SiteAdapter.DefineSingleEndpoint()
                .WithEndpoint<GetProfileRequest>()
                .WithMethod(Method.Get)
                .WithUrl(Config.UserDataUrl)
                .WithHeader("Accept", GITHUB_V3_ACCEPT)
                .WithHeader("Authorization", at => $"{at.AccessToken.Type} {at.AccessToken.Token}");

            //Define email endpoint, gets users email address
            SiteAdapter.DefineSingleEndpoint()
                .WithEndpoint<GetEmailRequest>()
                .WithMethod(Method.Get)
                .WithUrl(UserEmailUrl)
                .WithHeader("Authorization", at => $"{at.AccessToken.Type} {at.AccessToken.Token}")
                .WithHeader("Accept", GITHUB_V3_ACCEPT);
        }
       
        /*
         * Creates a repeatable, and source specific user id for 
         * GitHub users. This format is identical to the algorithim used
         * in the Auth0 Github connection, so it is compatible with Auth0
         */
        private static string GetUserIdFromPlatform(int userId)
        {
            return ManagedHash.ComputeHash($"github|{userId}", HashAlg.SHA1, HashEncodingMode.Hexadecimal);
        }


        protected override async Task<UserLoginData?> GetLoginDataAsync(IOAuthAccessState accessToken, CancellationToken cancellationToken)
        {
            GetProfileRequest req = new(accessToken);

            //Exec the get for the profile
            RestResponse profResponse = await SiteAdapter.ExecuteAsync(req, cancellationToken);

            if (!profResponse.IsSuccessful || profResponse.RawBytes == null)
            {
                Log.Debug("Github login data attempt responded with status code {code}", profResponse.StatusCode);
                return null;
            }

            GithubProfile profile = JsonSerializer.Deserialize<GithubProfile>(profResponse.RawBytes)!;

            if (profile.ID < 100)
            {
                Log.Debug("Github login data attempt responded with empty or invalid response body", profResponse.StatusCode);
                return null;
            }

            //Return login data
            return new()
            {
                //User-id is just the SHA 1 
                UserId = GetUserIdFromPlatform(profile.ID)
            };
        }

        protected override async Task<AccountData?> GetAccountDataAsync(IOAuthAccessState accessToken, CancellationToken cancellationToken = default)
        {
            AccountData? accountData = null;

            //Get the user's email address's
            GetEmailRequest request = new(accessToken);

            //get user's emails
            RestResponse getEmailResponse = await SiteAdapter.ExecuteAsync(request, cancellationToken);

            //Check status
            if (getEmailResponse.IsSuccessful && getEmailResponse.RawBytes != null)
            {
                //Filter emails addresses 
                foreach (EmailContainer email in JsonSerializer.Deserialize<EmailContainer[]>(getEmailResponse.RawBytes)!)
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

            //We need to get the user's profile again
            GetProfileRequest prof = new(accessToken);

            //Exec request against site adapter
            RestResponse profResponse = await SiteAdapter.ExecuteAsync(prof, cancellationToken);
            
            if (!profResponse.IsSuccessful || profResponse.RawBytes == null)
            {
                Log.Debug("Github account data request failed but GH responded with status code {code}", profResponse.StatusCode);
                return null;
            }

            //Deserialize the profile
            GithubProfile profile = JsonSerializer.Deserialize<GithubProfile>(profResponse.RawBytes)!;

            //Get the user's name from gh profile
            string[] names = profile.FullName!.Split(" ", StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            //setup the user's profile data
            accountData.First = names.Length > 0 ? names[0] : string.Empty;
            accountData.Last = names.Length > 1 ? names[1] : string.Empty;
            return accountData;
        }

        //Requests to get required data from github

        private sealed record class GetProfileRequest(IOAuthAccessState AccessToken)
        { }

        private sealed record class GetEmailRequest(IOAuthAccessState AccessToken)
        { }

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

    }
}