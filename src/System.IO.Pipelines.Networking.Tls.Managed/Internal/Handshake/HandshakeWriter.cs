using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.TlsSpec;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Handshake
{
    internal struct HandshakeWriter
    {
        private IConnectionState _state;
        private int _amountWritten;
        private Memory<byte> _bookmark;
        private int start;
        private HandshakeMessageType _messageType;

        public HandshakeWriter(ref WritableBuffer buffer, IConnectionState state, HandshakeMessageType messageType)
        {
            _messageType = messageType;
            start = buffer.BytesWritten;
            _state = state;
            buffer.WriteBigEndian(messageType);
            _bookmark = buffer.Memory;
            buffer.Advance(3);
            _amountWritten = buffer.BytesWritten;
        }

        public void Finish(ref WritableBuffer buffer)
        {
            var messageContent = buffer.BytesWritten - _amountWritten;
            BufferExtensions.Write24BitNumber(messageContent, _bookmark);
            _state.HandshakeHash?.HashData(buffer.AsReadableBuffer().Slice(_amountWritten-4));
        }
    }
}
