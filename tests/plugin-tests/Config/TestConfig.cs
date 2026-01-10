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
