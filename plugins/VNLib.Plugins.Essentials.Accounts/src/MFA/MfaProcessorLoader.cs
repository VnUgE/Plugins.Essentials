/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: MfaProcessorLoader.cs 
*
* MfaProcessorLoader.cs is part of VNLib.Plugins.Essentials.Accounts which
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

using System.Linq;
using System.Text.Json.Serialization;

using FluentValidation;

using VNLib.Utils.Logging;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Essentials.Accounts.MFA.Otp;
using VNLib.Plugins.Essentials.Accounts.MFA.Fido;
using VNLib.Plugins.Essentials.Accounts.MFA.Totp;

namespace VNLib.Plugins.Essentials.Accounts.MFA
{

    [ConfigurationName("mfa")]
    internal sealed class MfaProcessorLoader(PluginBase plugin, IConfigScope config)
    {
        private readonly bool Enabled = config.GetValueOrDefault("enabled", true);
        private readonly MfaProcessorConfig[] _processors = config.GetRequiredProperty<MfaProcessorConfig[]>("processors");

        /// <summary>
        /// The mfa system settings for the application
        /// </summary>
        public MfaConfig MfaSettings { get; } = config.DeserialzeAndValidate<MfaConfig>();

        /// <summary>
        /// Validates and loads the MFA processors defined in the configuration
        /// </summary>
        /// <returns>The array of loaded mfa processors for this plugin</returns>
        public IMfaProcessor[] GetProcessors()
        {
            ValidateConfig();

            if (!Enabled)
            {
                plugin.Log.Debug("MFA system is disabled, no processors will be loaded");
                return [];
            }

            //Build processor array from their loaded configuration objects
            IMfaProcessor[] procs = _processors
                .Where(static p => p.Enabled)   //Only load enabled processor
                .Select(GetProcessorForType)
                .Where(c => c != null)
                .ToArray()!;

            plugin.Log.Debug("Loaded {count} MFA processors: {data}", procs.Length, procs.Select(s => s.Type));

            return procs;
        }

        private void ValidateConfig()
        {
            InlineValidator<MfaProcessorLoader> val = new();

            val.RuleFor(static c => c._processors)
                .NotEmpty()
                .ForEach(static p =>
                {
                    p.ChildRules(val =>
                    {
                        val.RuleFor(p => p.ExernAssemblyPath)
                            .Matches(@"^[\w\-.]+\.dll$")
                            .When(val => val.Type == "external")
                            .WithMessage("The assembly path must be a valid DLL file");

                        val.RuleFor(p => p.Type)
                            .NotEmpty();
                    });
                });

            val.ValidateAndThrow(this);
        }

        private IMfaProcessor? GetProcessorForType(MfaProcessorConfig proc)
        {
            switch (proc.Type)
            {
                //Load an external assembly for the processor
                case "external":
                    plugin.Log.Debug("Loading external MFA processor from {asm}", proc.ExernAssemblyPath);

                    return plugin.CreateServiceExternal<IMfaProcessor>(proc.ExernAssemblyPath!);

                case "totp":
                    return plugin.GetOrCreateSingleton<TotpMfaProcessor>();

                case "fido":
                    return plugin.GetOrCreateSingleton<FidoMfaProcessor>();

                case "pkotp":
                    return plugin.GetOrCreateSingleton<OtpMfaProcessor>();

                default:
                    plugin.Log.Warn("Unknown MFA processor type '{type}', ignoring processor", proc.Type);
                    return null;
            }
        }


        private sealed class MfaProcessorConfig
        {
            [JsonPropertyName("enabled")]
            public bool Enabled { get; set; } = true;   //If the user defined a config but no enabled flag, assume they want it enabled

            /*
             * Define the processor type, an internal processor (like totp) or 
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
