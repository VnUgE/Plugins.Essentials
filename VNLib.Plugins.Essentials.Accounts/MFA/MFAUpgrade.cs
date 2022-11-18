using System.Text.Json.Serialization;

#nullable enable

namespace VNLib.Plugins.Essentials.Accounts.MFA
{
    internal class MFAUpgrade
    {
        /// <summary>
        /// The login's client id specifier
        /// </summary>
        [JsonPropertyName("cid")]
        public string? ClientID { get; set; }
        /// <summary>
        /// The id of the user that is requesting a login
        /// </summary>
        [JsonPropertyName("uname")]
        public string? UserName{ get; set; }
        /// <summary>
        /// The <see cref="MFAType"/> of the upgrade request
        /// </summary>
        [JsonPropertyName("type")]
        public MFAType Type { get; set; }
        /// <summary>
        /// The a base64 encoded string of the user's 
        /// public key
        /// </summary>
        [JsonPropertyName("pubkey")]
        public string? Base64PubKey { get; set; }
        /// <summary>
        /// The user's specified language
        /// </summary>
        [JsonPropertyName("lang")]
        public string? ClientLocalLanguage { get; set; }
        /// <summary>
        /// The encrypted password token for the client
        /// </summary>
        [JsonPropertyName("cd")]
        public string? PwClientData { get; set; }
    }
}
