using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using static System.IO.Pipelines.Networking.Tls.RecordProtocol.RecordUtils;

namespace System.IO.Pipelines.Networking.Tls.Handshake
{
    public class HandshakeWriter
    {
        public static void WriteHandshake(ref WritableBuffer buffer, IStateMachine stateMachine, HandshakeType type, RecordContentWriter contentWriter)
        {
            int start = buffer.BytesWritten;
            buffer.WriteBigEndian(type);
            Memory<byte> bookmark = buffer.Memory;
            buffer.Advance(3);
            int amountWritten = buffer.BytesWritten;

            contentWriter(ref buffer);

            var messageContent = buffer.BytesWritten - amountWritten;
            BufferExtensions.Write24BitNumber(messageContent, bookmark);
            stateMachine.HandshakeHash?.HashData(buffer.AsReadableBuffer().Slice(start));
        }
    }
}
