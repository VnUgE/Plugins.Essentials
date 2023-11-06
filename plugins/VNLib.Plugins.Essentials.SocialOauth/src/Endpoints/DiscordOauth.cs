/*
* Copyright (c) 2023 Vaughn Nugent
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
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Text.Json.Serialization;

using RestSharp;

using VNLib.Hashing;
using VNLib.Utils.Logging;
using VNLib.Plugins.Essentials.Accounts;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Net.Rest.Client.Construction;


namespace VNLib.Plugins.Essentials.SocialOauth.Endpoints
{
    [ConfigurationName("discord")]
    internal sealed class DiscordOauth : SocialOauthBase
    {
        public DiscordOauth(PluginBase plugin, IConfigScope config) : base(plugin, config)
        {
            //Define profile endpoint
            SiteAdapter.DefineSingleEndpoint()
                .WithEndpoint<DiscordProfileRequest>()
                .WithMethod(Method.Get)
                .WithUrl(Config.UserDataUrl)
                .WithHeader("Authorization", r => $"{r.AccessToken.Type} {r.AccessToken.Token}");
        }

        /*
         * Creates a user-id from the users discord username, that is repeatable 
         * and matches the Auth0 social user-id format
         */
        private static string GetUserIdFromPlatform(string userName) => $"discord|{userName}";


        ///<inheritdoc/>
        protected override async Task<AccountData?> GetAccountDataAsync(IOAuthAccessState accessToken, CancellationToken cancellationToken)
        {
            //Get the user's profile
            UserProfile? profile = await GetUserProfileAssync(accessToken, cancellationToken);

            if (profile == null)
            {
                return null;
            }

            //Make sure the user's account is verified
            if (!profile.Verified)
            {
                return null;
            }

            return new()
            {
                EmailAddress = profile.EmailAddress,
                First = profile.Username,
            };
        }

        ///<inheritdoc/>
        protected override async Task<UserLoginData?> GetLoginDataAsync(IOAuthAccessState accessToken, CancellationToken cancellationToken)
        {
            //Get the user's profile
            UserProfile? profile = await GetUserProfileAssync(accessToken, cancellationToken);

            if(profile == null)
            {
                return null;
            }

            return new()
            {
                //Get unique user-id from the discord profile and sha1 hex hash to store in db
                UserId = GetUserIdFromPlatform(profile.UserID)
            };
        }

        private async Task<UserProfile?> GetUserProfileAssync(IOAuthAccessState accessToken, CancellationToken cancellationToken)
        {
            //Get the user's email address's
            DiscordProfileRequest req = new(accessToken);
            RestResponse response = await SiteAdapter.ExecuteAsync(req, cancellationToken);

            //Check response
            if (!response.IsSuccessful || response.Content == null)
            {
                Log.Debug("Discord user request responded with code {code}:{data}", response.StatusCode, response.Content);
                return null;
            }

            UserProfile? discordProfile = JsonSerializer.Deserialize<UserProfile>(response.RawBytes);

            if (string.IsNullOrWhiteSpace(discordProfile?.UserID))
            {
                Log.Debug("Discord user request responded with invalid response data {code}:{data}", response.StatusCode, response.Content);
                return null;
            }

            return discordProfile;
        }

        private sealed record class DiscordProfileRequest(IOAuthAccessState AccessToken)
        { }

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
    }
}