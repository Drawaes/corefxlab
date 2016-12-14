using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal
{
    public struct FrameWriter
    {
        private Memory<byte> _bookmark;
        private int _amountWritten;
        public FrameWriter(ref WritableBuffer buffer,TlsFrameType frameType)
        {
            buffer.Ensure(5);
            buffer.WriteBigEndian(frameType);
            buffer.WriteBigEndian<ushort>(0x0303);

            _bookmark = buffer.Memory;
            buffer.Advance(2);
            _amountWritten = buffer.BytesWritten;
        }

        public void Finish(WritableBuffer buffer)
        {
            var recordSize = buffer.BytesWritten - _amountWritten;
            _bookmark.Span.Write((ushort)((recordSize >> 8) | (recordSize << 8)));
        }
    }
}
