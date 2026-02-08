/*
* Copyright (c) 2026 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Tests
* File: TestConfig.cs
*
* TestConfig.cs is part of VNLib.Plugins.Essentials.Tests which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Tests is free software: you can redistribute it and/or modify 
* it under the terms of the GNU General Public License as published
* by the Free Software Foundation, either version 2 of the License,
* or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Tests is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
* General Public License for more details.
*
* You should have received a copy of the GNU General Public License 
* along with VNLib.Plugins.Essentials.Tests. If not, see http://www.gnu.org/licenses/.
*/

using System;
using System.IO;

using VNLib.Plugins;
using VNLib.Plugins.Essentials.ServiceStack.Testing;

namespace Plugins.Essentials.Tests.Config
{
    internal static class TestConfig
    {
        private static string ConfigDirPath => Environment.GetEnvironmentVariable("TEST_CONFIG_DIR")!;

        /// <summary>
        /// Loads a plugin config file from the TEST_CONFIG_DIR environment variable directory
        /// </summary>
        public static TestPluginLoader<T> WithLocalPluignConfig<T>(this TestPluginLoader<T> pl, string file) where T : class, IPlugin, new()
        {
            string path = Path.Combine(ConfigDirPath, file);
            return pl.WithPluginConfigFile(path);
        }

        /// <summary>
        /// Loads the host config file from the TEST_CONFIG_DIR environment variable directory
        /// </summary>
        public static TestPluginLoader<T> WithLocalHostConfig<T>(this TestPluginLoader<T> pl) where T : class, IPlugin, new()
        {
            string path = Path.Combine(ConfigDirPath, "Test.Plugins.Essentials.Config.json");
            return pl.WithHostConfigFile(path);
        }

        public static TestPluginLoader<T> WithExternalPluginConfig<T>(this TestPluginLoader<T> pl, string file) where T : class, IPlugin, new()
        {
            return pl.WithPluginConfigFile(file);
        }
    }
}
