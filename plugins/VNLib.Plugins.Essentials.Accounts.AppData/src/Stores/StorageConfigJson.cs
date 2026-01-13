/*
* Copyright (c) 2026 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts.AppData
* File: StorageConfigJson.cs 
*
* StorageConfigJson.cs is part of VNLib.Plugins.Essentials.Accounts.AppData which 
* is part of the larger VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Accounts is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Accounts is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

using System.Text.Json.Serialization;

using FluentValidation;

using VNLib.Plugins.Extensions.Loading;

namespace VNLib.Plugins.Essentials.Accounts.AppData.Stores
{
    /// <summary>
    /// Base configuration model for storage backend selection and validation
    /// </summary>
    internal class StorageConfigJson : IOnConfigValidation
    {
        /// <summary>
        /// The storage backend type. Currently only 'sql' is supported.
        /// </summary>
        [JsonPropertyName("type")]
        public string Type { get; set; } = "sql";

        public virtual void OnValidate()
        {
            InlineValidator<StorageConfigJson> val = [];

            val.RuleFor(x => x.Type)
                .NotEmpty()
                .WithMessage("Config property 'storage.type' must be specified.")
                .Matches("^(sql)$")
                .WithMessage("Config property 'storage.type' must be 'sql'.");

            val.ValidateAndThrow(this);
        }
    }
}
