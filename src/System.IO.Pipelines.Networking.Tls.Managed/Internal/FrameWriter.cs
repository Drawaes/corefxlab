using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal
{
    internal struct FrameWriter
    {
        private Memory<byte> _bookmark;
        private DisposableReservation _reservation;
        private int _amountWritten;
        private ConnectionState _state;
        private TlsFrameType _frameType;
        private int _encryptedDataStart;

        public FrameWriter(ref WritableBuffer buffer, TlsFrameType frameType, ConnectionState state)
        {
            _frameType = frameType;
            _state = state;
            buffer.Ensure(5);
            buffer.WriteBigEndian(frameType);
            buffer.WriteBigEndian<ushort>(0x0303);

            _bookmark = buffer.Memory;
            _reservation = buffer.Memory.Reserve();
            buffer.Advance(2);
            _amountWritten = buffer.BytesWritten;
                        
            if (state.ServerDataEncrypted && state.CipherSuite.BulkCipher.NounceSaltLength > 0)
            {
                //Add Explicit nounce data
                buffer.Ensure(sizeof(ulong));
                buffer.WriteBigEndian(state.ServerKey.SequenceNumber);
            }
            _encryptedDataStart = buffer.BytesWritten;
        }

        public void Finish(ref WritableBuffer buffer)
        {
            if(_state.ServerDataEncrypted)
            {
                _state.ServerKey.Encrypt(ref buffer, buffer.AsReadableBuffer().Slice(_encryptedDataStart) ,_frameType, _state);
            }

            var recordSize = buffer.BytesWritten - _amountWritten;
            _bookmark.Span.Write((ushort)((recordSize >> 8) | (recordSize << 8)));
            _reservation.Dispose();
            _bookmark = Memory<byte>.Empty;
        }
    }
}
