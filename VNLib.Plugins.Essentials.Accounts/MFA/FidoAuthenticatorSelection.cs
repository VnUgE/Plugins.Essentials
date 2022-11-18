using System.Text.Json.Serialization;

#nullable enable

namespace VNLib.Plugins.Essentials.Accounts.MFA
{
    class FidoAuthenticatorSelection
    {
        [JsonPropertyName("requireResidentKey")]
        public bool RequireResidentKey { get; set; } = false;
        [JsonPropertyName("authenticatorAttachment")]
        public string? AuthenticatorAttachment { get; set; } = "cross-platform";
        [JsonPropertyName("userVerification")]
        public string? UserVerification { get; set; } = "required";
    }
}
