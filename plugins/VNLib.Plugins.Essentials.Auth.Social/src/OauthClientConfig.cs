﻿/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Auth.Social
* File: OauthClientConfig.cs 
*
* OauthClientConfig.cs is part of VNLib.Plugins.Essentials.Auth.Social which is part of the larger 
* VNLib collection of libraries and utilities.
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
using System.Net;
using System.Collections.Generic;

using VNLib.Utils.Logging;
using VNLib.Utils.Extensions;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Essentials.Auth.Social.openid;
using VNLib.Plugins.Extensions.Loading.Configuration;

namespace VNLib.Plugins.Essentials.Auth.Social
{

    /// <summary>
    /// Contains the standard configuration data for an OAuth2 endpoint
    /// defined by plugin configuration
    /// </summary>
    public sealed class OauthClientConfig
    {

        public OauthClientConfig(PluginBase plugin, IConfigScope config)
        {
            EndpointPath = config.GetRequiredProperty("path", p => p.GetString()!);
            AccountOrigin = config.GetRequiredProperty("account_origin", p => p.GetString()!);
         
            OpenIdPortalConfig portalConf = config.Deserialze<OpenIdPortalConfig>()!;

            Validate.NotNull(portalConf.AuthorizationEndpoint, $"Missing authorization endpoint for {config.ScopeName}");
            Validate.NotNull(portalConf.TokenEndpoint, $"Missing token endpoint for {config.ScopeName}");
            Validate.NotNull(portalConf.UserDataEndpoint, $"Missing user-data endpoint for {config.ScopeName}");

            //Create the uris 
            AuthorizationUrl = new(portalConf.AuthorizationEndpoint);
            AccessTokenUrl = new(portalConf.TokenEndpoint);
            UserDataUrl = new(portalConf.UserDataEndpoint);

            AllowForLocalAccounts = config.GetValueOrDefault("allow_for_local", p => p.GetBoolean(), false);
            AllowRegistration = config.GetValueOrDefault("allow_registration", p => p.GetBoolean(), false);
            NonceByteSize = config.GetRequiredProperty("nonce_size", p => p.GetUInt32());
            RandomPasswordSize = config.GetRequiredProperty("password_size", p => p.GetInt32());
            InitClaimValidFor = config.GetRequiredProperty("claim_valid_for_sec", p => p.GetTimeSpan(TimeParseType.Seconds));

            //Setup async lazy loaders for secrets
            ClientID = plugin.GetSecretAsync($"{config.ScopeName}_client_id")
                            .ToLazy(static r => r.Result.ToString());

            ClientSecret = plugin.GetSecretAsync($"{config.ScopeName}_client_secret")
                                .ToLazy(static r => r.Result.ToString());

            //Log the token server ip address for the user to verify
            if (plugin.Log.IsEnabled(LogLevel.Verbose))
            {
                _ = plugin.ObserveWork(async () =>
                {
                    IPAddress[] addresses = await Dns.GetHostAddressesAsync(AccessTokenUrl.DnsSafeHost);
                    plugin.Log.Verbose("Token server {host} resolves to {ip}", AccessTokenUrl.DnsSafeHost, addresses);
                });
            }
        }

        /// <summary>
        /// The client ID for the OAuth2 service
        /// </summary>
        public IAsyncLazy<string> ClientID { get; } 
       
        /// <summary>
        /// The client secret for the OAuth2 service
        /// </summary>
        public IAsyncLazy<string> ClientSecret { get; }


        /// <summary>
        /// The user-account origin value. Specifies that the user account
        /// was created outside of the local account system
        /// </summary>        
        public string AccountOrigin { get; }

        /// <summary>
        /// The URL to redirect the user to the OAuth2 service
        /// to begin the authentication process
        /// </summary>       
        public Uri AuthorizationUrl { get; }

        /// <summary>
        /// The remote endoint to exchange codes for access tokens
        /// </summary>
        public Uri AccessTokenUrl { get; }

        /// <summary>
        /// The endpoint to get user-data object from
        /// </summary>
        public Uri UserDataUrl { get; }

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

        /// <summary>
        /// The initial time the login claim is valid for
        /// </summary>
        public TimeSpan InitClaimValidFor { get; }
    }
}
