/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Oauth
* File: UserApplication.cs 
*
* UserApplication.cs is part of VNLib.Plugins.Essentials.Oauth which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Oauth is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Oauth is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

using System;
using System.Text.Json;
using System.ComponentModel;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

using VNLib.Utils.Memory;
using VNLib.Utils.Extensions;
using VNLib.Hashing.IdentityUtility;
using VNLib.Plugins.Extensions.Data;
using VNLib.Plugins.Extensions.Data.Abstractions;

using IndexAttribute = Microsoft.EntityFrameworkCore.IndexAttribute;


namespace VNLib.Plugins.Essentials.Oauth.Applications
{
    /// <summary>
    /// Represents an OAuth2 application for a user
    /// </summary>
    [Index(nameof(ClientId), IsUnique = true)]
    public class UserApplication : DbModelBase, IUserEntity, IJsonOnDeserialized
    {
        ///<inheritdoc/>
        [Key, Required]
        public override string? Id { get; set; }
        ///<inheritdoc/>
        public override DateTime Created { get; set; }
        ///<inheritdoc/>
        public override DateTime LastModified { get; set; }

        ///<inheritdoc/>
        [Required]
        [JsonIgnore]
        public string? UserId { get; set; }

        /// <summary>
        /// The OAuth2 application's associated client-id
        /// </summary>
        [Required]
        [JsonPropertyName("client_id")]
        public string? ClientId { get; set; }

        /// <summary>
        /// The hash of the application's secret (no json-serializable)
        /// </summary>
        [JsonIgnore]
        [MaxLength(1000)]
        public string? SecretHash { get; set; }

        /// <summary>
        /// The user-defined name of the application
        /// </summary>
        [DisplayName("Application Name")]
        [JsonPropertyName("name")]
        public string? AppName { get; set; }

        /// <summary>
        /// The user-defined description for the application
        /// </summary>
        [JsonPropertyName("description")]
        [DisplayName("Application Description")]
        public string? AppDescription { get; set; }

        /// <summary>
        /// The permissions for the application
        /// </summary>
        [JsonPropertyName("permissions")]
        [Column("permissions")]
        public string? Permissions { get; set; }


        [NotMapped]
        [JsonIgnore]
        public PrivateString? RawSecret { get; set; }

        void IJsonOnDeserialized.OnDeserialized()
        {
            Id = Id?.Trim();
            ClientId = ClientId?.Trim();
            UserId = UserId?.Trim();
            AppName = AppName?.Trim();
            AppDescription = AppDescription?.Trim();
            Permissions = Permissions?.Trim();
        }


        /// <summary>
        /// Creates a new <see cref="UserApplication"/> instance
        /// from the supplied <see cref="JsonElement"/> assuming 
        /// JWT format
        /// </summary>
        /// <param name="appEl">The application JWT payalod element</param>
        /// <returns>The recovered application</returns>
        public static UserApplication FromJwtDoc(JsonElement appEl)
        {
            return new()
            {
                UserId = appEl.GetPropString("sub"),
                ClientId = appEl.GetPropString("azp"),
                Id = appEl.GetPropString("appid"),
                Permissions = appEl.GetPropString("scope"),
            };
        }
        /// <summary>
        /// Stores the 
        /// </summary>
        /// <param name="app">The application to serialze to JWT format</param>
        /// <param name="dict">Jwt dictionary payload</param>
        public static void ToJwtDict(UserApplication app, IDictionary<string, string?> dict)
        {
            dict["appid"] = app.Id;
            dict["azp"] = app.ClientId;
            dict["sub"] = app.UserId;
            dict["scope"] = app.Permissions;
        }

        /// <summary>
        /// Stores the 
        /// </summary>
        /// <param name="app"></param>
        /// <param name="payload">JW payload parameter</param>
        public static void ToJwtPayload(UserApplication app, in JwtPayload payload)
        {
            payload["appid"] = app.Id;
            payload["azp"] = app.ClientId;
            payload["sub"] = app.UserId;
            payload["scope"] = app.Permissions;
        }
    }
}