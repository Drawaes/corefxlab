using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.TlsSpec;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal
{
    internal struct FrameWriter
    {
        private TlsFrameType _frameType;
        private Memory<byte> _bookmark;
        private int _amountWrittenBefore;
        private IConnectionState _state;
        private int _encryptedDataStart;

        public FrameWriter(ref WritableBuffer buffer, TlsFrameType frameType, IConnectionState state)
        {
            _frameType = frameType;
            _state = state;
            buffer.Ensure(5);
            buffer.WriteBigEndian(frameType);
            buffer.WriteBigEndian(state.TlsVersion);
            _bookmark = buffer.Memory;
            buffer.Advance(2);
            _amountWrittenBefore = buffer.BytesWritten;

            if(state.EncryptingServer)
            {
                state.ServerKey.WriteExplicitNonce(ref buffer);
            }
            _encryptedDataStart = buffer.BytesWritten;
        }

        public void Finish(ref WritableBuffer buffer)
        {
            if (_state.EncryptingServer)
            {
                _state.ServerKey.Encrypt(ref buffer, buffer.AsReadableBuffer().Slice(_encryptedDataStart), _frameType, _state);
            }
            var recordSize = buffer.BytesWritten - _amountWrittenBefore;
            _bookmark.Span.Write((ushort)((recordSize >> 8) | (recordSize << 8)));
            _bookmark = Memory<byte>.Empty;

        }
    }
}
