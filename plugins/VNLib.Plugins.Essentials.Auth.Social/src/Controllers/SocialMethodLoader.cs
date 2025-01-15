/*
* Copyright (c) 2025 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Auth.Social
* File: SocialMethodLoader.cs 
*
* SocialMethodLoader.cs is part of VNLib.Plugins.Essentials.Auth.Social which 
* is part of the larger VNLib collection of libraries and utilities.
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

using System.Linq;
using System.Text.Json;
using System.Collections.Generic;
using System.Text.Json.Serialization;

using FluentValidation;

using VNLib.Utils.Logging;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Essentials.Auth.Social.OpenIDConnect;

namespace VNLib.Plugins.Essentials.Auth.Social.Controllers
{
    [ConfigurationName("social_oauth")]
    internal sealed class SocialMethodLoader(PluginBase plugin, IConfigScope config)
    {
        private readonly MethodConfigValidator _methodValidator = new();
        private readonly ILogProvider _log = plugin.Log.CreateScope("SocialMethodLoader");

        /// <summary>
        /// Retruns all the loaded Social OAuth login methods from the loaded controllers
        /// </summary>
        /// <returns>All methods loaded by this plugin</returns>
        public ISocialOauthMethod[] LoadAllMethods()
        {
            IEnumerable<JsonElement> methods = config.GetRequiredProperty<IEnumerable<JsonElement>>(
                property: "methods", 
                static p => p.EnumerateArray()
            );

            return methods
                .Select(GetController)
                .Where(static c => c is not null)
                .SelectMany(static c => c!.GetMethods())
                .ToArray();
        }

        private ISocialOauthController? GetController(JsonElement conf)
        {
            OAuthMethodConfig methodConfig = conf.Deserialize<OAuthMethodConfig>()!;
            if (!methodConfig.Enabled)
            {
                return null;
            }
            
            _methodValidator.ValidateAndThrow(methodConfig);

            switch (methodConfig.Type)
            {
                //Load an external assembly for the processor
                case "external":
                    _log.Debug("Loading external Social OAuth2 provider from {asm}", methodConfig.ExernAssemblyPath);

                    return plugin.CreateServiceExternal<ISocialOauthController>(methodConfig.ExernAssemblyPath!);

                case "oidc":
                    OpenIDConnectMethod oidc = new (plugin, conf);

                    //Oidc needs to be configured in the background
                    _ = plugin.ConfigureServiceAsync(oidc, 200);

                    return oidc;

                default:
                    _log.Warn("Unknown social OAuth controller type '{type}', ignoring controller", methodConfig.Type);
                    return null;
            }
        }

      

        private sealed class MethodConfigValidator: AbstractValidator<OAuthMethodConfig>
        {
            public MethodConfigValidator()
            {
                RuleFor(c => c.ExernAssemblyPath)
                    .Matches(@"^[\w\-.]+\.dll$")
                    .When(c => c.Type == "external")
                    .WithMessage("The assembly path must be a valid DLL file");

                RuleFor(c => c.Type)
                    .NotEmpty()
                    .Matches(@"^(external|oidc)$");
            }
        }

        private sealed class OAuthMethodConfig
        {
            [JsonPropertyName("enabled")]
            public bool Enabled { get; set; } = true;   //If the user defined a config but no enabled flag, assume they want it enabled

            /*
             * Define the processor type, an internal processor (like github) or 
             * an external processor loaded in via and external .NET assembly
             */
            [JsonPropertyName("type")]
            public string? Type { get; set; }

            /*
             * Dll asset file path to load the external assembly from
             * if the processor type is set to "external"
             */
            [JsonPropertyName("assembly_path")]
            public string? ExernAssemblyPath { get; set; }
        }
    }
}
