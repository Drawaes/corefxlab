using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed
{
    public class TlsRecordWriter<T> where T : IMessageWriter, new()
    {
        private readonly T _messageWriter;

        public TlsRecordWriter()
        {
            _messageWriter = new T();
        }

        public void WriteMessage(ref WritableBuffer buffer, ManagedConnectionContext context)
        {
            buffer.Ensure(5);
            buffer.WriteBigEndian(_messageWriter.MessageType);
            buffer.WriteBigEndian<ushort>(0x0303);

            using (var reserved = buffer.Memory.Reserve())
            {
                var bookmark = buffer.Memory.Span;
                buffer.Advance(2);
                var amountWritten = buffer.BytesWritten;

                _messageWriter.WriteMessage(ref buffer, context);

                var recordSize = buffer.BytesWritten - amountWritten;
                bookmark.Write((ushort)((recordSize >> 8) | (recordSize << 8)));
            }
        }
    }
}
