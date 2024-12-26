using Microsoft.VisualStudio.TestTools.UnitTesting;

using Plugins.Essentials.Tests.Config;

using VNLib.Plugins.Essentials.Oauth.ClientApps;

using VNLib.Plugins.Essentials.Runtime;
using VNLib.Plugins.Essentials.ServiceStack.Testing;

namespace Plugins.Essentials.Tests.Oauth2
{
    [TestClass()]
    public class Oauth2AppPluginTest
    {
        [TestMethod()]
        public void LoadOauth2ClientAppPluginTest()
        {
            new TestPluginLoader<ClientAppsEntry>()
                .WithCliArgs(["--verbose"])
                .WithLocalHostConfig()
                .WithLocalPluignConfig("Essentials.Oauth.ClientApps.json")
                .Load()
                .GetServices(services =>
                {
                    //Only virtual endpoints should be exposed
                    Assert.AreEqual(1, services.Count);
                    Assert.IsTrue(services.HasService<IVirtualEndpointDefinition>());

                    //Scopes and Applications endpoints should be loaded
                    Assert.AreEqual(2, services.GetEndpoints().Length);
                })
                .Unload(delayMilliseconds: 5000)
                .TryDispose();
        }
    }
}
