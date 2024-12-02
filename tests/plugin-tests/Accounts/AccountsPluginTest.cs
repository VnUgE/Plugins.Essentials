using Microsoft.VisualStudio.TestTools.UnitTesting;

using System;
using System.Linq;
using System.Collections.Generic;

using VNLib.Plugins.Essentials.Accounts;
using VNLib.Plugins.Essentials.Middleware;
using VNLib.Plugins.Essentials.Runtime;
using VNLib.Plugins.Essentials.ServiceStack.Testing;

namespace Plugins.Essentials.Tests.Accounts
{

    [TestClass()]
    public class AccountsPluginTest
    {
        private static string HostConfigFilePath => Environment.GetEnvironmentVariable("TEST_HOST_CONFIG_FILE")!;

        [TestMethod()]
        public void LoadAccountsPlugin()
        {
            new TestPluginLoader<AccountsEntryPoint>()
                .WithCliArgs(["--verbose", "--account-setup"])  //Enable verbose logging and account setup mode
                .WithHostConfigFile(HostConfigFilePath)
                .WithPluginConfigFile("Essentials.Accounts.json")
                .Load()
                .GetServices(services =>
                {
                    Assert.IsTrue(services.HasService<IAccountSecurityProvider>());
                    Assert.IsTrue(services.HasService<IEnumerable<IHttpMiddleware>>());
                    Assert.IsTrue(services.HasService<IVirtualEndpointDefinition>());

                    //Sec provider, middleware, and virtual endpoints must be loaded
                    Assert.AreEqual(3, services.Count);

                    //Only 1 endpoint should be loaded for accounts (the rpc endpoint)
                    Assert.AreEqual(1, services.GetEndpoints().Length);

                    //Must export the security provider as middleware also
                    //Assert.AreEqual(1, services.GetService<IEnumerable<IHttpMiddleware>>().Count());
                })
                .Unload(delayMilliseconds: 3500)
                .TryDispose();
        }
    }
}
