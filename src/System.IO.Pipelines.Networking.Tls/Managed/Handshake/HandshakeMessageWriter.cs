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
            BufferExtensions.Write24BitNumber(messageContent, messageContentSize);
            if (!context.ServerDataEncrypted)
            {
                context.HandshakeHash.HashData(buffer.AsReadableBuffer().Slice(5));
            }
        }

        
    }
}
