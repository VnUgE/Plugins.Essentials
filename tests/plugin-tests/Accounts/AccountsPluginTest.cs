/*
* Copyright (c) 2026 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Tests
* File: AccountsPluginTest.cs
*
* AccountsPluginTest.cs is part of VNLib.Plugins.Essentials.Tests which is part of the larger 
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

using VNLib.Plugins.Essentials.Accounts;
using VNLib.Plugins.Essentials.Middleware;
using VNLib.Plugins.Essentials.Runtime;
using VNLib.Plugins.Essentials.ServiceStack.Testing;

using Plugins.Essentials.Tests.Config;

namespace Plugins.Essentials.Tests.Accounts
{

    [TestClass()]
    public class AccountsPluginTest
    {
        [TestMethod()]
        public void LoadAccountsPlugin()
        {
            new TestPluginLoader<AccountsEntryPoint>()
                .WithCliArgs(["--verbose", "--account-setup"])  //Enable verbose logging and account setup mode
                .WithLocalHostConfig()
                .WithExternalPluginConfig("Essentials.Accounts.json")
                .Load()
                .GetServices(services =>
                {
                    Assert.IsTrue(services.HasService<IAccountSecurityProvider>());
                    Assert.IsTrue(services.HasService<IEnumerable<IHttpMiddleware>>());
                    Assert.IsTrue(services.HasService<IVirtualEndpointDefinition>());

                    //Sec provider, middleware, and virtual endpoints must be loaded
                    Assert.AreEqual(3, services.Count);

                    //Only 1 endpoint should be loaded for accounts (the rpc endpoint)
                    Assert.HasCount(1, services.GetEndpoints());

                    //Must export the security provider as middleware also
                    //Assert.AreEqual(1, services.GetService<IEnumerable<IHttpMiddleware>>().Count());
                })
                .Unload(delayMilliseconds: 5000)
                .TryDispose();
        }
    }
}
