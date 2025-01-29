/*
* Copyright (c) 2025 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Auth.Social
* File: OpenIdIdentityTokenJson.cs 
*
* OpenIdIdentityTokenJson.cs is part of VNLib.Plugins.Essentials.Auth.Social which is 
* part of the larger VNLib collection of libraries and utilities.
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
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;


namespace VNLib.Plugins.Essentials.Auth.Social.OpenIDConnect
{
    internal sealed class OpenIdIdentityTokenJson
    {
        [JsonPropertyName("iss")]
        public string? Issuer { get; set; }

        [JsonPropertyName("aud")]
        [JsonConverter(typeof(FlexibleStringArrayConverter))]
        public string[]? Audience { get; set; }

        [JsonPropertyName("exp")]
        public long Expiration { get; set; }

        [JsonPropertyName("iat")]
        public long IssuedAt { get; set; }

        [JsonPropertyName("sub")]
        public string? Subject { get; set; }

        [JsonPropertyName("picture")]
        public string? Picture { get; set; }

        /*
         * Some identity providers (Discord namely) return an arary of strings for 
         * the audience claim. This converter allows for the audience claim to be
         * a single string or an array of strings.
         */
        public class FlexibleStringArrayConverter : JsonConverter<string[]>
        {
            public override string[] Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
            {
                if (reader.TokenType == JsonTokenType.String)
                {
                    // If it's a single string, wrap it in an array
                    return [reader.GetString()];
                }
                else if (reader.TokenType == JsonTokenType.StartArray)
                {
                    // If it's an array, deserialize it as-is
                    List<string> items = [];
                    while (reader.Read())
                    {
                        switch (reader.TokenType)
                        {
                            case JsonTokenType.String:
                                items.Add(reader.GetString());
                                break;
                            case JsonTokenType.EndArray:
                                goto Exit;
                            default:
                                throw new JsonException($"Expected a string value in the array not {reader.TokenType}");
                        }
                    }
                
                Exit:
                    return [.. items];
                }
                else
                {
                    throw new JsonException("Expected a string or an array of strings.");
                }
            }

            public override void Write(Utf8JsonWriter writer, string[] value, JsonSerializerOptions options)
            {
                if (value.Length == 1)
                {
                    // If there's only one string, write it as a string
                    writer.WriteStringValue(value[0]);
                }
                else
                {
                    // Otherwise, write it as an array
                    writer.WriteStartArray();

                    Array.ForEach(value, writer.WriteStringValue);

                    writer.WriteEndArray();
                }
            }
        }

    }
}
