using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal
{
    internal struct FrameWriter
    {
        private Memory<byte> _bookmark;
        private int _amountWritten;
        private ConnectionState _state;
        private ReadCursor _encryptedDataCursor;
        private TlsFrameType _frameType;

        public FrameWriter(ref WritableBuffer buffer, TlsFrameType frameType, ConnectionState state)
        {
            _frameType = frameType;
            _state = state;
            buffer.Ensure(5);
            buffer.WriteBigEndian(frameType);
            buffer.WriteBigEndian<ushort>(0x0303);

            _bookmark = buffer.Memory;
            buffer.Advance(2);
            _amountWritten = buffer.BytesWritten;

            _encryptedDataCursor = buffer.AsReadableBuffer().End;
            if (state.ServerDataEncrypted && state.CipherSuite.BulkCipher.NounceSaltLength > 0)
            {
                //Add Explicit nounce data
                buffer.Ensure(sizeof(ulong));
                buffer.WriteBigEndian(state.ServerKey.SequenceNumber);
            }
        }

        public void Finish(ref WritableBuffer buffer)
        {
            if(_state.ServerDataEncrypted)
            {
                var finalRecordSize = buffer.BytesWritten - _amountWritten - sizeof(ulong);
                byte[] additionalData = new byte[13];
                var addSpan = new Span<byte>(additionalData);
                addSpan.Write64BitNumber(_state.ServerKey.SequenceNumber);
                addSpan = addSpan.Slice(8);
                addSpan.Write(_frameType);
                addSpan = addSpan.Slice(1);
                addSpan.Write((byte)0x03);
                addSpan = addSpan.Slice(1);
                addSpan.Write((byte)0x03);
                addSpan = addSpan.Slice(1);
                addSpan.Write16BitNumber((ushort)(finalRecordSize));
                byte[] authTag;
                var result = _state.ServerKey.Encrypt(buffer.AsReadableBuffer().Slice(13).ToArray(), additionalData, out authTag);
                var readable = buffer.AsReadableBuffer().First;
                readable = readable.Slice(13);
                var r = new Span<byte>(result);
                r.CopyTo(readable.Span);
                buffer.Write(new Span<byte>(authTag));
            }

            var recordSize = buffer.BytesWritten - _amountWritten;
            _bookmark.Span.Write((ushort)((recordSize >> 8) | (recordSize << 8)));
        }
    }
}
