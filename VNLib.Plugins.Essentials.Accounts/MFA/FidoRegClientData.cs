using System.Text.Json.Serialization;

#nullable enable

namespace VNLib.Plugins.Essentials.Accounts.MFA
{
    internal class FidoRegClientData
    {
        [JsonPropertyName("challenge")]
        public string? Challenge { get; set; }
        [JsonPropertyName("origin")]
        public string? Origin { get; set; }
        [JsonPropertyName("type")]
        public string? Type { get; set; }
    }
}
