/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts.AppData
* File: IAppDataStore.cs 
*
* IAppDataStore.cs is part of VNLib.Plugins.Essentials.Accounts.AppData which 
* is part of the larger VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Accounts is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Accounts is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

using System.Threading;
using System.Threading.Tasks;

namespace VNLib.Plugins.Essentials.Accounts.AppData.Model
{
    internal interface IAppDataStore
    {
        Task<UserRecordData?> GetRecordAsync(string userId, string recordKey, RecordOpFlags flags, CancellationToken cancellation);

        Task SetRecordAsync(string userId, string recordKey, byte[] data, ulong checksum, RecordOpFlags flags, CancellationToken cancellation);

        Task DeleteRecordAsync(string userId, string recordKey, CancellationToken cancellation);
    }
}
