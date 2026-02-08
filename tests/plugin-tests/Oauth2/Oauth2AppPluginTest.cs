/*
* Copyright (c) 2026 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Tests
* File: Oauth2AppPluginTest.cs
*
* Oauth2AppPluginTest.cs is part of VNLib.Plugins.Essentials.Tests which is part of the larger 
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

using Microsoft.VisualStudio.TestTools.UnitTesting;

using VNLib.Plugins.Essentials.Oauth.ClientApps;
using VNLib.Plugins.Essentials.Runtime;
using VNLib.Plugins.Essentials.ServiceStack.Testing;

using Plugins.Essentials.Tests.Config;

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
                    Assert.HasCount(2, services.GetEndpoints());
                })
                .Unload(delayMilliseconds: 5000)
                .TryDispose();
        }
    }
}
