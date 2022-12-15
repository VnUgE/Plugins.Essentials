﻿/*
* Copyright (c) 2022 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts.Registration
* File: EmailSystemConfig.cs 
*
* EmailSystemConfig.cs is part of VNLib.Plugins.Essentials.Accounts.Registration which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Accounts.Registration is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Accounts.Registration is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

using System;
using System.Text;
using System.Text.Json;

using RestSharp;

using Emails.Transactional.Client;

using VNLib.Utils.Extensions;
using VNLib.Net.Rest.Client;
using VNLib.Net.Rest.Client.OAuth2;
using VNLib.Plugins.Extensions.Loading;

namespace VNLib.Plugins.Essentials.Accounts.Registration
{
    /// <summary>
    /// An extended <see cref="TransactionalEmailConfig"/> configuration 
    /// object that contains a <see cref="Net.Rest.Client.RestClientPool"/> pool for making 
    /// transactions
    /// </summary>
    internal sealed class EmailSystemConfig : TransactionalEmailConfig
    {
        public const string REG_TEMPLATE_NAME = "Registration";

        public EmailSystemConfig(PluginBase pbase)
        {
            IReadOnlyDictionary<string, JsonElement> conf = pbase.GetConfig("email");
            EmailFromName = conf["from_name"].GetString() ?? throw new KeyNotFoundException("");
            EmailFromAddress = conf["from_address"].GetString() ?? throw new KeyNotFoundException("");
            Uri baseServerPath = new(conf["base_url"].GetString()!, UriKind.RelativeOrAbsolute);
            Uri tokenServerBase = new(conf["token_server_url"].GetString()!, UriKind.RelativeOrAbsolute);
            Uri transactionEndpoint = new(conf["transaction_path"].GetString()!, UriKind.RelativeOrAbsolute);
            //Load templates
            Dictionary<string, string> templates = conf["templates"].EnumerateObject().ToDictionary(jp => jp.Name, jp => jp.Value.GetString()!);
            //Init base config
            WithTemplates(templates)
            .WithUrl(transactionEndpoint);
            //Load credentials
            string authEndpoint = conf["token_path"].GetString() ?? throw new KeyNotFoundException();
            int maxClients = conf["max_clients"].GetInt32();

            
            //Load oauth secrets from vault
            Task<SecretResult?> oauth2ClientID = pbase.TryGetSecretAsync("oauth2_client_id");
            Task<SecretResult?> oauth2Password = pbase.TryGetSecretAsync("oauth2_client_secret");

            //Lazy cred loaded, tasks should be loaded before this method will ever get called
            Credential lazyCredentialGet()
            {
                //Load the results 
                SecretResult cliendId = oauth2ClientID.Result ?? throw new KeyNotFoundException("Missing required oauth2 client id");
                SecretResult password = oauth2Password.Result ?? throw new KeyNotFoundException("Missing required oauth2 client secret");

                //Creat credential
                return Credential.Create(cliendId.Result, password.Result);
            }


            //Init client creation options
            RestClientOptions poolOptions = new()
            {
                AllowMultipleDefaultParametersWithSameName = true,
                AutomaticDecompression = System.Net.DecompressionMethods.All,
                PreAuthenticate = true,
                Encoding = Encoding.UTF8,
                MaxTimeout = conf["request_timeout_ms"].GetInt32(),
                UserAgent = "Essentials.EmailRegistation",
                FollowRedirects = false,
                BaseUrl = baseServerPath
            };
            //Options for auth token endpoint
            RestClientOptions oAuth2ClientOptions = new()
            {
                AllowMultipleDefaultParametersWithSameName = true,
                AutomaticDecompression = System.Net.DecompressionMethods.All,
                PreAuthenticate = false,
                Encoding = Encoding.UTF8,
                MaxTimeout = conf["request_timeout_ms"].GetInt32(),
                UserAgent = "Essentials.EmailRegistation",
                FollowRedirects = false,
                BaseUrl = baseServerPath
            };

            //Init Oauth authenticator
            OAuth2Authenticator authenticator = new(oAuth2ClientOptions, lazyCredentialGet, authEndpoint);            
            //Store pool
            RestClientPool = new(maxClients, poolOptions, authenticator:authenticator);

            void Cleanup()
            {
                authenticator.Dispose();
                RestClientPool.Dispose();
                oauth2ClientID.Dispose();
                oauth2Password.Dispose();
            }

            //register password cleanup
            _ = pbase.UnloadToken.RegisterUnobserved(Cleanup);
        }

        /// <summary>
        /// A shared <see cref="Net.Rest.Client.RestClientPool"/> for renting configuraed 
        /// <see cref="RestClient"/>
        /// </summary>
        public RestClientPool RestClientPool { get; }
        /// <summary>
        /// A global from email address name
        /// </summary>
        public string EmailFromName { get; }
        /// <summary>
        /// A global from email address
        /// </summary>
        public string EmailFromAddress { get; }

        /// <summary>
        /// Prepares a new registration email transaction request
        /// </summary>
        /// <returns>The prepared <see cref="EmailTransactionRequest"/> object</returns>
        public EmailTransactionRequest GetRegistrationMessage()
        {
            EmailTransactionRequest req = GetTemplateRequest(REG_TEMPLATE_NAME);
            req.FromAddress = EmailFromAddress;
            req.FromName = EmailFromName;
            //set reg subject
            req.Subject = "One more step to register";
            return req;
        }
    }
}