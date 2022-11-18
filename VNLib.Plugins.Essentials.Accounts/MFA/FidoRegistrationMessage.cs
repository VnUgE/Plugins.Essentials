using System.Text.Json.Serialization;

#nullable enable

namespace VNLib.Plugins.Essentials.Accounts.MFA
{
    /// <summary>
    /// Represents a fido device registration message to be sent
    /// to a currently signed in user
    /// </summary>
    class FidoRegistrationMessage
    {
        [JsonPropertyName("id")]
        public string? GuidUserId { get; set; }
        [JsonPropertyName("challenge")]
        public string? Base64Challenge { get; set; } = null;
        [JsonPropertyName("timeout")]
        public int Timeout { get; set; } = 60000;
        [JsonPropertyName("cose_alg")]
        public int CoseAlgNumber { get; set; }
        [JsonPropertyName("rp_name")]
        public string? SiteName { get; set; }
        [JsonPropertyName("attestation")]
        public string? AttestationType { get; set; } = "none";
        [JsonPropertyName("authenticatorSelection")]
        public FidoAuthenticatorSelection? AuthSelection { get; set; } = new();
    }
}
