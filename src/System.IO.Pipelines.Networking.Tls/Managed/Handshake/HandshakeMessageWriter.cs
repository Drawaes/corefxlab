using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Handshake
{
    public class HandshakeMessageWriter<T> :IMessageWriter  where T : IMessageWriter, new()
    {
        private T _messageWriter;

        public byte MessageType => (byte)TlsFrameType.Handshake;

        public HandshakeMessageWriter()
        {
            _messageWriter = new T();
        }

        public void WriteMessage(ref WritableBuffer buffer, ManagedConnectionContext context)
        {
            buffer.WriteBigEndian(_messageWriter.MessageType);
            var messageContentSize = buffer.Memory;
            var messageContentCurrentSize = buffer.BytesWritten + 3;
            buffer.WriteBigEndian<ushort>(0);
            buffer.WriteBigEndian<byte>(0);

            _messageWriter.WriteMessage(ref buffer, context);
            
            var messageContent = buffer.BytesWritten - messageContentCurrentSize;
            Write24BitNumber(messageContent, messageContentSize);
            context.HandshakeHash.HashData(buffer.AsReadableBuffer().Slice(5));
        }

        internal static void Write24BitNumber(int numberToWrite, Memory<byte> buffer)
        {
            buffer.Span.Write((byte)(((numberToWrite & 0xFF0000) >> 16)));
            buffer.Span.Slice(1).Write((byte)(((numberToWrite & 0x00ff00) >> 8)));
            buffer.Span.Slice(2).Write((byte)(numberToWrite & 0x0000ff));
        }
        internal static void Write24BitNumber(int numberToWrite, ref WritableBuffer buffer)
        {
            buffer.Ensure(3);
            buffer.WriteBigEndian((byte)(((numberToWrite & 0xFF0000) >> 16)));
            buffer.WriteBigEndian((byte)(((numberToWrite & 0x00ff00) >> 8)));
            buffer.WriteBigEndian((byte)(numberToWrite & 0x0000ff));
        }
    }
}
