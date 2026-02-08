/*
* Copyright (c) 2026 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Tests
* File: SessionProviderTesting.cs
*
* SessionProviderTesting.cs is part of VNLib.Plugins.Essentials.Tests which is part of the larger 
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

using VNLib.Plugins.Essentials.Middleware;
using VNLib.Plugins.Essentials.Runtime;
using VNLib.Plugins.Essentials.ServiceStack.Testing;
using VNLib.Plugins.Essentials.Sessions;

using Plugins.Essentials.Tests.Config;

namespace Plugins.Essentials.Tests.Sessions
{
    [TestClass()]
    public class SessionProviderTesting
    {
        [TestMethod()]
        public void LoadSessionProvider()
        {
            new TestPluginLoader<SessionProviderEntry>()
                .WithCliArgs(["--verbose"])  //Enable verbose logging
                .WithLocalHostConfig()
                .WithLocalPluignConfig("SessionProvider.json")
                .Load()
                .GetServices(services =>
                {
                    Assert.IsTrue(services.HasService<ISessionProvider>());
                    Assert.IsTrue(services.HasService<IVirtualEndpointDefinition>());
                    Assert.IsTrue(services.HasService<IEnumerable<IHttpMiddleware>>());
                    Assert.AreEqual(3, services.Count);

                    //Oauth token and revoke endpoints should be loaded
                    Assert.HasCount(2, services.GetEndpoints());

                    //Session security middleware is enabled
                    Assert.HasCount(1, services.GetService<IEnumerable<IHttpMiddleware>>());
                })
                .Unload(delayMilliseconds: 5000)
                .TryDispose();
        }
    }
}
