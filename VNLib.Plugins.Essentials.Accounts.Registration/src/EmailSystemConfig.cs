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
            Task<string?> oauth2ClientID = pbase.TryGetSecretAsync("oauth2_client_id");
            Task<string?> oauth2Password = pbase.TryGetSecretAsync("oauth2_client_secret");

            //Lazy cred loaded, tasks should be loaded before this method will ever get called
            Credential lazyCredentialGet()
            {
                //Load the results 
                string cliendId = oauth2ClientID.Result ?? throw new KeyNotFoundException("Missing required oauth2 client id");
                string password = oauth2Password.Result ?? throw new KeyNotFoundException("Missing required oauth2 client secret");

                return Credential.Create(cliendId, password);
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