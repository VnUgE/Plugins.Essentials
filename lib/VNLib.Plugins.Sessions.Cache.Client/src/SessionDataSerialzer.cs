﻿/*
* Copyright (c) 2025 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Sessions.Cache.Client
* File: SessionDataSerialzer.cs 
*
* SessionDataSerialzer.cs is part of VNLib.Plugins.Sessions.Cache.Client which is part of the larger 
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
using System.Text;
using System.IO;
using System.Buffers;
using System.Diagnostics;
using System.Collections.Generic;

using VNLib.Utils.Memory;
using VNLib.Utils.Logging;
using VNLib.Utils.Extensions;
using VNLib.Data.Caching;

namespace VNLib.Plugins.Sessions.Cache.Client
{

    /// <summary>
    /// Very basic session data serializer memory optimized for key-value
    /// string pairs
    /// </summary>
    internal sealed class SessionDataSerialzer : ICacheObjectSerializer, ICacheObjectDeserializer
    {
        const string KV_DELIMITER = "\0\0";

        readonly int CharBufferSize;
        readonly ILogProvider? _debugLog;

        public SessionDataSerialzer(int charBufferSize, ILogProvider? debugLog)
        {
            CharBufferSize = charBufferSize;
            _debugLog = debugLog;
            debugLog?.Warn("Sensitive session logging is enabled. This will leak session data!");
        }

        [Conditional("DEBUG")]
        private void DebugSessionItems(IDictionary<string, string> sessionData, bool serializing)
        {
            if (_debugLog is null)
            {
                return;
            }

            StringBuilder sdBuilder = new();
            foreach (KeyValuePair<string, string> item in sessionData)
            {
                sdBuilder.Append(item.Key);
                sdBuilder.Append('=');
                sdBuilder.Append(item.Value);
                sdBuilder.Append(", ");
            }

            if (serializing)
            {
                _debugLog.Debug("Serialzing session data: {sd} ", sdBuilder);
            }
            else
            {
                _debugLog.Debug("Deserialzing session data: {sd} ", sdBuilder);
            }
        }

        T? ICacheObjectDeserializer.Deserialize<T>(ReadOnlySpan<byte> objectData) where T : default
        {
            if (!typeof(T).IsAssignableTo(typeof(IDictionary<string, string>)))
            {
                throw new NotSupportedException("This deserialzer only supports IDictionary<string,string>");
            }

            //Get char count from bin buffer
            int charCount = Encoding.UTF8.GetCharCount(objectData);

            //Alloc decode buffer
            using UnsafeMemoryHandle<char> charBuffer = MemoryUtil.UnsafeAllocNearestPage<char>(charCount, true);

            //decode chars
            Encoding.UTF8.GetChars(objectData, charBuffer.Span);

            //Alloc new dict to write strings to
            Dictionary<string, string> output = new(StringComparer.OrdinalIgnoreCase);

            //Reader to track position of char buffer
            ForwardOnlyReader<char> reader = new(charBuffer.Span[0..charCount]);

            //Read data from the object data buffer
            while (reader.WindowSize > 0)
            {
                //get index of next separator
                int sep = GetNextToken(ref reader);

                //No more separators are found, skip
                if (sep == -1)
                {
                    break;
                }

                //Get pointer to key before reading value
                ReadOnlySpan<char> key = reader.Window[0..sep];

                //Advance reader to next sequence
                reader.Advance(sep + KV_DELIMITER.Length);

                //Find next sepearator to recover the value
                sep = GetNextToken(ref reader);

                if (sep == -1)
                {
                    break;
                }

                //Store value
                ReadOnlySpan<char> value = reader.Window[0..sep];

                //Set the kvp in the dict
                output[key.ToString()] = value.ToString();

                //Advance reader again
                reader.Advance(sep + 2);
            }

            DebugSessionItems(output, false);

            return (T?)(output as object);
        }

        private static int GetNextToken(ref ForwardOnlyReader<char> reader)
            => reader.Window.IndexOf(KV_DELIMITER);

        void ICacheObjectSerializer.Serialize<T>(T obj, Stream finiteStream)
        {
            if (obj is not Dictionary<string, string> dict)
            {
                throw new NotSupportedException("Data type is not supported by this serializer");
            }

            // Write debug info
            DebugSessionItems(dict, true);

            // In some instance (such as FBM) a buffer writer may be on the stream interface
            // so we can use it to write the serialized data if we have access to it.
            if (finiteStream is IBufferWriter<byte> bufferWriter)
            {                
                WriteToOutput(
                    dict,
                    bufferWriter: bufferWriter,
                    stream: null,
                    streamBuffer: default
                );
            }
            else
            {
                // Only allocate the stream buffer if we're working with a Stream
                using UnsafeMemoryHandle<byte> streamBuffer = MemoryUtil.UnsafeAllocNearestPage<byte>(CharBufferSize, true);

                WriteToOutput(
                    dict,
                    bufferWriter: null,
                    stream: finiteStream,
                    streamBuffer.Span
                );
            }
        }

        private void WriteToOutput(Dictionary<string, string> dict, IBufferWriter<byte>? bufferWriter, Stream? stream, Span<byte> streamBuffer)
        {
            //Alloc char buffer, sessions should be under 16k 
            using UnsafeMemoryHandle<char> charBuffer = MemoryUtil.UnsafeAllocNearestPage<char>(CharBufferSize);

            using Dictionary<string, string>.Enumerator e = dict.GetEnumerator();

            ForwardOnlyWriter<char> writer = new(charBuffer.Span);

            while (e.MoveNext())
            {
                KeyValuePair<string, string> element = e.Current;

                /*
                 * confim there is enough room in the writer, if there is not
                 * flush to the buffer writer or stream
                 */
                if (element.Key.Length + element.Value.Length + 4 > writer.RemainingSize)
                {
                    FlushWriter(in writer, bufferWriter, stream, streamBuffer);

                    //Reset the writer
                    writer.Reset();
                }

                //Add key/value elements
                writer.AppendSmall(element.Key);
                writer.AppendSmall(KV_DELIMITER);
                writer.Append(element.Value);
                writer.AppendSmall(KV_DELIMITER);
            }

            //encode remaining data
            FlushWriter(in writer, bufferWriter, stream, streamBuffer);
        }

        private static void FlushWriter(
            in ForwardOnlyWriter<char> writer,
            IBufferWriter<byte>? bufferWriter,
            Stream? stream,
            Span<byte> streamBuffer
        )
        {
            if (bufferWriter != null)
            {
                Encoding.UTF8.GetBytes(writer.AsSpan(), bufferWriter);
            }
            else if (stream != null)
            {
                Debug.Assert(!streamBuffer.IsEmpty, "Stream buffer should be allocated and have a length greater than 0");

                int bytesEncoded = Encoding.UTF8.GetBytes(writer.AsSpan(), streamBuffer);
                stream.Write(streamBuffer[..bytesEncoded]);
            }
            else
            {
                Debug.Fail("No stream or buffer is an undefined condition that should never happen");
                throw new InvalidOperationException("No output stream or buffer writer provided for serialization.");
            }
        }
    }
}
