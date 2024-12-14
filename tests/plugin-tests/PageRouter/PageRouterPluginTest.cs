using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;

using VNLib.Plugins.Essentials.Runtime;
using VNLib.Plugins.Essentials.ServiceStack.Testing;
using VNLib.Plugins.Essentials.Content.Routing;
using VNLib.Plugins.Essentials.Content;
using VNLib.Plugins.Essentials.Middleware;

using Plugins.Essentials.Tests.Config;

namespace Plugins.Essentials.Tests.PageRouter
{

    [TestClass()]
    public class PageRouterPluginTest
    {
        [TestMethod()]
        public void LoadPageRouterPlugin()
        {
            new TestPluginLoader<PageRouterEntry>()
                .WithCliArgs(["--verbose"])
                .WithLocalHostConfig()
                .WithLocalPluignConfig("PageRouter.json")
                .Load()
                .GetServices(services =>
                {
                    //Should not export any routes or middleware
                    Assert.IsFalse(services.HasService<IVirtualEndpointDefinition>());
                    Assert.IsFalse(services.HasService<IEnumerable<IHttpMiddleware>>());

                    //Only exports page router
                    Assert.AreEqual(1, services.Count);

                    Assert.IsTrue(services.HasService<IPageRouter>());

                })
                .Unload(delayMilliseconds: 5000)
                .TryDispose();
        }
    }
}
