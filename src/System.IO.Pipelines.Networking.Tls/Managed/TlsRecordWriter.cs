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
            ulong serverSequenceNumber = 0;
            buffer.Ensure(5);
            buffer.WriteBigEndian(_messageWriter.MessageType);
            buffer.WriteBigEndian<ushort>(0x0303);

            var bookmark = buffer.Memory.Span;
            buffer.Advance(2);
            var amountWritten = buffer.BytesWritten;

            if (context.ServerDataEncrypted)
            {
                //Add Explicit nounce data
                buffer.Ensure(8);
                serverSequenceNumber = context.GetServerSequenceNumber();
                buffer.WriteBigEndian(serverSequenceNumber);
            }

            var encryptedDataCursor = buffer.AsReadableBuffer().End;

            _messageWriter.WriteMessage(ref buffer, context);

            if (context.ServerDataEncrypted)
            {
                var finalRecordSize = buffer.BytesWritten - amountWritten - 8;
                byte[] additionalData = new byte[13];
                var addSpan = new Span<byte>(additionalData);
                addSpan.Write64BitNumber(serverSequenceNumber);
                addSpan = addSpan.Slice(8);
                addSpan.Write(_messageWriter.MessageType);
                addSpan = addSpan.Slice(1);
                addSpan.Write((byte)0x03);
                addSpan = addSpan.Slice(1);
                addSpan.Write((byte)0x03);
                addSpan = addSpan.Slice(1);
                addSpan.Write16BitNumber((ushort)(finalRecordSize));
                var nounce = context.GetServerNounce(serverSequenceNumber);
                byte[] authTag;
                var result = context.ServerKey.Encrypt(nounce, buffer.AsReadableBuffer().Slice(13).ToArray(), additionalData, out authTag);
                var readable = buffer.AsReadableBuffer().First;
                readable = readable.Slice(13);
                var r = new Span<byte>(result);
                r.CopyTo(readable.Span);
                buffer.Write(new Span<byte>(authTag));
            }

            var recordSize = buffer.BytesWritten - amountWritten;
            bookmark.Write((ushort)((recordSize >> 8) | (recordSize << 8)));
        }
    }
}
