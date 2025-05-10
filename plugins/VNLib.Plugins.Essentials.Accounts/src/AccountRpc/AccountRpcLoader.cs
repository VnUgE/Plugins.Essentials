/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: AccountRpcLoader.cs 
*
* AccountRpcLoader.cs is part of VNLib.Plugins.Essentials.Accounts which
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
using VNLib.Plugins.Essentials.Accounts.Controllers;


namespace VNLib.Plugins.Essentials.Accounts.AccountRpc
{
    [ConfigurationName("rpc")]
    internal sealed class AccountRpcLoader(PluginBase plugin, IConfigScope config)
    {
        private readonly RpcControllerConfig[] _methodConfigs = config.GetRequiredProperty<RpcControllerConfig[]>("methods");

        /// <summary>
        /// Retruns all the loaded account rpc methods from the loaded controllers
        /// </summary>
        /// <returns>All rpc methods loaded by this plugin</returns>
        public IAccountRpcMethod[] LoadAllMethods()
        {
            ValidateConfig();

            return _methodConfigs
                .Where(static c => c.Enabled)
                .Select(GetController)
                .Where(static c => c != null)
                .SelectMany(static c => c!.GetMethods())
                .ToArray();
        }

        private IAccountRpcController? GetController(RpcControllerConfig method)
        {
            switch (method.Type)
            {
                //Load an external assembly for the processor
                case "external":
                    plugin.Log.Debug("Loading external rpc controller from {asm}", method.ExernAssemblyPath);

                    return plugin.CreateServiceExternal<IAccountRpcController>(method.ExernAssemblyPath!);

                case "login":
                    return plugin.GetOrCreateSingleton<LoginController>();

                case "otp-auth":
                    //Otp is still experimental so let the user know
                    plugin.Log.Information("PK-OTP Authentication is enabled");
                    return plugin.GetOrCreateSingleton<OtpLoginController>();

                case "heartbeat":
                    return plugin.GetOrCreateSingleton<HeartbeatController>();

                case "profile":
                    return plugin.GetOrCreateSingleton<ProfileController>();

                case "password-reset":
                    return plugin.GetOrCreateSingleton<PasswordResetController>();

                default:
                    plugin.Log.Warn("Unknown rpc controller type '{type}', ignoring controller", method.Type);
                    return null;
            }
        }

        private void ValidateConfig()
        {
            InlineValidator<AccountRpcLoader> val = new();

            val.RuleFor(c => c._methodConfigs)
                .NotEmpty()
                .ForEach(p =>
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

        private sealed class RpcControllerConfig
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
