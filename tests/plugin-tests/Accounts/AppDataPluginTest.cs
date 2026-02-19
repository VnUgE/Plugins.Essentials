/*
* Copyright (c) 2026 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Tests
* File: AppDataPluginTest.cs
*
* AppDataPluginTest.cs is part of VNLib.Plugins.Essentials.Tests which is part of the larger 
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

using VNLib.Plugins.Essentials.Accounts.AppData;
using VNLib.Plugins.Essentials.Runtime;
using VNLib.Plugins.Essentials.ServiceStack.Testing;

using Plugins.Essentials.Tests.Config;

namespace Plugins.Essentials.Tests.Accounts
{
    [TestClass()]
    public class AppDataPluginTest
    {
        [TestMethod()]
        public void LoadAppDataPlugin()
        {
            new TestPluginLoader<AppDataEntry>()
                .WithCliArgs(["--verbose"])
                .WithLocalHostConfig()
                .WithLocalPluignConfig("Essentials.AppData.json")
                .Load()
                .GetServices(services =>
                {
                    Assert.IsTrue(services.HasService<IVirtualEndpointDefinition>());

                    Assert.AreEqual(1, services.Count);

                    //Only 1 endpoint should be loaded for app-data
                    Assert.HasCount(1, services.GetEndpoints());
                })
                .Unload(delayMilliseconds: 5000)
                .TryDispose();
        }
    }
}
