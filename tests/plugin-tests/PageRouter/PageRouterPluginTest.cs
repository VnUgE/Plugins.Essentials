/*
* Copyright (c) 2026 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Tests
* File: PageRouterPluginTest.cs
*
* PageRouterPluginTest.cs is part of VNLib.Plugins.Essentials.Tests which is part of the larger 
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

using System.Collections.Generic;

using Microsoft.VisualStudio.TestTools.UnitTesting;

using VNLib.Plugins.Essentials.Content;
using VNLib.Plugins.Essentials.Content.Routing;
using VNLib.Plugins.Essentials.Middleware;
using VNLib.Plugins.Essentials.Runtime;
using VNLib.Plugins.Essentials.ServiceStack.Testing;

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
