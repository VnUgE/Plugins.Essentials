using Microsoft.VisualStudio.TestTools.UnitTesting;

using System;

using VNLib.Plugins.Essentials.Accounts.AppData;
using VNLib.Plugins.Essentials.Runtime;
using VNLib.Plugins.Essentials.ServiceStack.Testing;

namespace Plugins.Essentials.Tests.Accounts
{
    [TestClass()]
    public class AppDataPluginTest
    {
        private static string HostConfigFilePath => Environment.GetEnvironmentVariable("TEST_HOST_CONFIG_FILE")!;

        [TestMethod()]
        public void LoadAppDataPlugin()
        {
            new TestPluginLoader<AppDataEntry>()
                .WithCliArgs(["--verbose"])
                .WithHostConfigFile(HostConfigFilePath)
                .WithPluginConfigFile("Essentials.AppData.json")
                .Load()
                .GetServices(services =>
                {
                    Assert.IsTrue(services.HasService<IVirtualEndpointDefinition>());

                    Assert.AreEqual(1, services.Count);

                    //Only 1 endpoint should be loaded for app-data
                    Assert.AreEqual(1, services.GetEndpoints().Length);
                })
                .Unload(delayMilliseconds: 3000)
                .TryDispose();
        }
    }
}
