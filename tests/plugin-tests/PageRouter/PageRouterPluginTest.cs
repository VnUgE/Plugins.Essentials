using Microsoft.VisualStudio.TestTools.UnitTesting;

using System;
using System.Collections.Generic;

using VNLib.Plugins.Essentials.Runtime;
using VNLib.Plugins.Essentials.ServiceStack.Testing;
using VNLib.Plugins.Essentials.Content.Routing;
using VNLib.Plugins.Essentials.Content;
using VNLib.Plugins.Essentials.Middleware;

namespace Plugins.Essentials.Tests.PageRouter
{
    [TestClass()]
    public class PageRouterPluginTest
    {
        private static string HostConfigFilePath => Environment.GetEnvironmentVariable("TEST_HOST_CONFIG_FILE")!;

        //Load local test route file
        private const string StoreConfig = @"{ ""store"": { ""route_file"": ""../../..//PageRouter/test-routes.xml"" } }";

        [TestMethod()]
        public void LoadPageRouterPlugin()
        {
            new TestPluginLoader<PageRouterEntry>()
                .WithCliArgs(["--verbose"])
                .WithHostConfigFile(HostConfigFilePath)
                .WithPluginConfigData(StoreConfig)
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
                .Unload(delayMilliseconds: 2000)
                .TryDispose();
        }
    }
}
