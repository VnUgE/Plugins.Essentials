using System.Text.Json.Serialization;

namespace VNLib.Plugins.Essentials.Accounts.Registration.Endpoints
{
    internal class RegRequestMessage
    {
        [JsonPropertyName("localtime")]
        public DateTimeOffset Timestamp { get; set; }

        [JsonPropertyName("username")]
        public string? UserName { get; set; }

        [JsonPropertyName("clientid")]
        public string? ClientId { get; set; }
    }
}