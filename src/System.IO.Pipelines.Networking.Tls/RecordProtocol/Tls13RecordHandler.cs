using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using static System.IO.Pipelines.Networking.Tls.RecordProtocol.RecordUtils;

namespace System.IO.Pipelines.Networking.Tls.RecordProtocol
{
    public class Tls13RecordHandler : IRecordHandler
    {
        public RecordType ProcessRecord(ref ReadableBuffer messageBuffer)
        {
            var recordType = messageBuffer.ReadBigEndian<RecordType>();
            messageBuffer = messageBuffer.Slice(RecordHeaderLength);
            return recordType;
        }

        public void WriteRecord(ref WritableBuffer buffer, RecordType recordType, RecordContentWriter innerMethod)
        {
            buffer.Ensure(sizeof(ushort) + sizeof(TlsVersion) + sizeof(RecordType));
            buffer.WriteBigEndian(recordType);
            buffer.WriteBigEndian(TlsVersion.Tls1);
            Memory<byte> bookmark = buffer.Memory;
            buffer.Advance(sizeof(ushort));
            int amountWrittenBefore = buffer.BytesWritten;

            innerMethod(ref buffer);

            int recordSize = buffer.BytesWritten - amountWrittenBefore;
            bookmark.Span.Write16BitNumber((ushort)recordSize);
        }
    }
}
