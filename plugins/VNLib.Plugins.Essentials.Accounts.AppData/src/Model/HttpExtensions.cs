/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts.AppData
* File: HttpExtensions.cs 
*
* HttpExtensions.cs is part of VNLib.Plugins.Essentials.Accounts.AppData which 
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

using System;
using System.Net;

using VNLib.Net.Http;

namespace VNLib.Plugins.Essentials.Accounts.AppData.Model
{
    internal static class HttpExtensions
    {
        const string ChecksumHeader = "X-Data-Checksum";

        public static void SetRecordResponse(this HttpEntity entity, UserRecordData record, HttpStatusCode code)
        {
            //Set checksum header
            entity.Server.Headers.Append(ChecksumHeader, $"{record.Checksum}");

            //Set the response to a new memory reader with the record data
            entity.CloseResponse(
                code, 
                ContentType.Binary,
                new BinDataRecordReader(record.Data)
            );
        }

        public static ulong? GetUserDataChecksum(this IConnectionInfo server)
        {
            string? checksumStr = server.Headers[ChecksumHeader];
            return string.IsNullOrWhiteSpace(checksumStr) && ulong.TryParse(checksumStr, out ulong checksum) ? checksum : null;
        }

        sealed class BinDataRecordReader(byte[] recordData) : IMemoryResponseReader
        {
            private int _read;

            ///<inheritdoc/>
            public int Remaining => recordData.Length - _read;

            ///<inheritdoc/>
            public void Advance(int written) => _read += written;

            ///<inheritdoc/>
            public void Close()
            {
                //No-op
            }

            ///<inheritdoc/>
            public ReadOnlyMemory<byte> GetMemory() => recordData.AsMemory(_read);
        }
    }
}
