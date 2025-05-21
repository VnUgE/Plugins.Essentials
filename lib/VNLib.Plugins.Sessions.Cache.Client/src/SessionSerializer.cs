/*
* Copyright (c) 2025 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Sessions.Cache.Client
* File: SessionSerializer.cs 
*
* SessionSerializer.cs is part of VNLib.Plugins.Sessions.Cache.Client which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Sessions.Cache.Client is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Sessions.Cache.Client is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

using System;
using System.Threading;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

using VNLib.Utils.Async;

namespace VNLib.Plugins.Sessions.Cache.Client
{

    /// <summary>
    /// Concrete <see cref="ISessionSerialzer{TSession}"/> that provides 
    /// access serialization for session types
    /// </summary>
    /// <typeparam name="TSession">The session type</typeparam>
    /// <remarks>
    /// Initializes a new <see cref="SessionSerializer{TSession}"/>
    /// </remarks>
    /// <param name="poolCapacity">The maximum number of wait entry instances to hold in memory cache</param>
    public class SessionSerializer<TSession>(int poolCapacity) 
        : AsyncAccessSerializer<TSession>(poolCapacity, initialCapacity: 0, null),
        ISessionSerialzer<TSession> where TSession : IRemoteSession
    {
        /*
         * This implementation uses an internal store for wait entires
         * that uses a string key instead of using the moniker directly,
         * but inherits the concrete serialzer class to reuse the built 
         * in helper types and methods in the AsyncAccessSerializer class.
         * 
         * The utils library is also currently the only lib that has 
         * automated testing, so that helps us.
         * 
         * This is to allow sessions to be recovered from their session
         * id instead of a session instance. All public api method calls
         * are intercepted and routed to the internal wait table
         */

        private readonly Dictionary<string, WaitEntry> _waitTable = new(poolCapacity, StringComparer.Ordinal);

        ///<inheritdoc/>
        public virtual bool TryGetSession(string sessionId, [NotNullWhen(true)] out TSession? session)
        {
            lock (StoreLock)
            {
                //Try to see if an entry is loaded, and get the session
                bool result = _waitTable.TryGetValue(sessionId, out WaitEntry? entry);
                session = result ? entry!.Moniker : default;
                return result;
            }
        }

        ///<inheritdoc/>
        public override Task WaitAsync(TSession moniker, CancellationToken cancellation = default)
        {
            //Token must not be cancelled 
            cancellation.ThrowIfCancellationRequested();

            WaitEnterToken token;
            WaitEntry? wait;

            if (cancellation.CanBeCanceled)
            {
                lock (StoreLock)
                {
                    //See if the entry already exists, otherwise get a new wait entry
                    if (!_waitTable.TryGetValue(moniker.SessionID, out wait))
                    {
                        GetWaitEntry(ref wait, moniker);

                        //Add entry to store
                        _waitTable[moniker.SessionID] = wait;
                    }

                    //Get waiter before leaving lock
                    wait.ScheduleWait(cancellation, out token);
                }

                //Enter wait and setup cancellation continuation
                return EnterCancellableWait(in token, wait);
            }
            else
            {
                lock (StoreLock)
                {
                    //See if the entry already exists, otherwise get a new wait entry
                    if (!WaitTable.TryGetValue(moniker, out wait))
                    {
                        GetWaitEntry(ref wait, moniker);

                        //Add entry to store
                        WaitTable[moniker] = wait;
                    }

                    //Get waiter before leaving lock
                    wait.ScheduleWait(out token);
                }

                //Enter the waiter without any cancellation support
                return token.EnterWaitAsync();
            }
        }

        ///<inheritdoc/>
        public override void Release(TSession moniker)
        {            
            WaitReleaseToken releaser;

            do
            {
                lock (StoreLock)
                {
                    WaitEntry entry = _waitTable[moniker.SessionID];

                    //Call release while holding store lock
                    if (entry.ExitWait(out releaser) == 0)
                    {
                        //No more waiters
                        _waitTable.Remove(moniker.SessionID);

                        /*
                         * We must release the semaphore before returning to pool, 
                         * its safe because there are no more waiters
                         */
                        bool result = releaser.Release();
                        Debug.Assert(result, "Expected a wait token to return true when released with 0 waiting threads");

                        ReturnEntry(entry);

                        //already released
                        releaser = default;
                    }
                }
            //See base class for why we need to loop
            } while (!releaser.Release());
        }

        ///<inheritdoc/>
        public new void CacheHardClear()
        {
            base.CacheHardClear();
            lock (StoreLock)
            {
                _waitTable.TrimExcess();
            }
        }
     
    }
}
