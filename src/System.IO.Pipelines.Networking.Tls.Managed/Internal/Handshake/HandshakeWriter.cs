using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Handshake
{
    internal struct HandshakeWriter
    {
        private ConnectionState _state;
        private int _amountWritten;
        private Memory<byte> _bookmark;
        private DisposableReservation _reservation;

        public HandshakeWriter(ref WritableBuffer buffer, ConnectionState state, HandshakeMessageType messageType)
        {
            _state = state;
            buffer.WriteBigEndian(messageType);
            _bookmark = buffer.Memory;
            _reservation = buffer.Memory.Reserve();
            buffer.Advance(3);
            _amountWritten = buffer.BytesWritten;
        }

        public void Finish(ref WritableBuffer buffer)
        {
            var messageContent = buffer.BytesWritten - _amountWritten;
            BufferExtensions.Write24BitNumber(messageContent, _bookmark);
            if (! _state.ServerDataEncrypted)
            {
                var readableBuffer = buffer.AsReadableBuffer().Slice(_amountWritten - 4);
                _state.HandshakeHash.HashData(readableBuffer);
            }
            _reservation.Dispose();
        }
    }
}
