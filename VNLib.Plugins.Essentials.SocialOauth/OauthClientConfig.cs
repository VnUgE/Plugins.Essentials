/*
* Copyright (c) 2022 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.SocialOauth
* File: OauthClientConfig.cs 
*
* OauthClientConfig.cs is part of VNLib.Plugins.Essentials.SocialOauth which is part of the larger 
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
using System.Collections.Generic;

using VNLib.Utils.Extensions;
using VNLib.Plugins.Essentials.Users;
using VNLib.Plugins.Essentials.Accounts;
using VNLib.Net.Rest.Client;

#nullable enable

namespace VNLib.Plugins.Essentials.SocialOauth
{

    public sealed class OauthClientConfig
    {

        public OauthClientConfig(string configName, IReadOnlyDictionary<string, JsonElement> config)
        {
            EndpointPath = config["path"].GetString() ?? throw new KeyNotFoundException($"Missing required key 'path' in config {configName}");

            //Set discord account origin
            AccountOrigin = config["account_origin"].GetString() ?? throw new KeyNotFoundException($"Missing required key 'account_origin' in config {configName}");
           
            //Get the auth and token urls
            string authUrl = config["authorization_url"].GetString() ?? throw new KeyNotFoundException($"Missing required key 'authorization_url' in config {configName}");
            string tokenUrl = config["token_url"].GetString() ?? throw new KeyNotFoundException($"Missing required key 'token_url' in config {configName}");
            string userUrl = config["user_data_url"].GetString() ?? throw new KeyNotFoundException($"Missing required key 'user_data_url' in config {configName}");
            //Create the uris 
            AccessCodeUrl = new(authUrl);
            AccessTokenUrl = new(tokenUrl);
            UserDataUrl = new(userUrl);

            AllowForLocalAccounts = config["allow_for_local"].GetBoolean();
            AllowRegistration = config["allow_registration"].GetBoolean();
            LoginNonceLifetime = config["valid_for_sec"].GetTimeSpan(TimeParseType.Seconds);
            NonceByteSize = config["nonce_size"].GetUInt32();
            RandomPasswordSize = config["password_size"].GetInt32();
        }


        public RestClientPool ClientPool { get; }

        public string ClientID { get; init; }
       
        public string ClientSecret { get; init; }

       
        /// <summary>
        /// The user-account origin value. Specifies that the user account
        /// was created outside of the local account system
        /// </summary>        
        public string AccountOrigin { get; }

        /// <summary>
        /// The URL to redirect the user to the OAuth2 service
        /// to begin the authentication process
        /// </summary>       
        public Uri AccessCodeUrl { get; }

        /// <summary>
        /// The remote endoint to exchange codes for access tokens
        /// </summary>
        public Uri AccessTokenUrl { get; }

        /// <summary>
        /// The endpoint to get user-data object from
        /// </summary>
        public Uri UserDataUrl { get; }

        public TimeSpan LoginNonceLifetime { get; }
        /// <summary>
        /// The user store to create/get users from
        /// </summary>     
        public IUserManager Users { get; init; }
      
        public PasswordHashing Passwords { get; init; }

        /// <summary>
        /// The endpoint route/path
        /// </summary>       
        public string EndpointPath { get; }
        
        /// <summary>
        /// The size (in bytes) of the random generated nonce
        /// </summary>      
        public uint NonceByteSize { get; }

        /// <summary>
        /// A value that specifies if locally created accounts are allowed 
        /// to be logged in from an OAuth2 source
        /// </summary>        
        public bool AllowForLocalAccounts { get; }

        /// <summary>
        /// A value that indicates if accounts that do not exist will be created
        /// and logged in immediatly, on successfull OAuth2 flow
        /// </summary>       
        public bool AllowRegistration { get; }
        
        /// <summary>
        /// The size (in bytes) of the random password generated for new users
        /// </summary>
        public int RandomPasswordSize { get; }
    }
}
