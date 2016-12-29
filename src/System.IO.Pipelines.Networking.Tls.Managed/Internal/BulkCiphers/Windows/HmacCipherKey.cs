using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Windows;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.TlsSpec;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Windows;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
using static global::Interop.BCrypt;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.BulkCiphers.Windows
{
    internal class HmacCipherKey : IBulkCipherInstance
    {
        private NativeBufferPool _pool;
        private SafeBCryptKeyHandle _handle;
        private ulong _sequenceNumber;
        private OwnedMemory<byte> _buffer;
        private int _blockLength;
        private CipherSuite _suite;
        private byte[] _hmacKey;
        private byte[] _iv = new byte[16];

        public unsafe HmacCipherKey(SafeBCryptAlgorithmHandle provider, CipherSuite suite, NativeBufferPool pool, int bufferSizeNeeded, byte* keyPointer, int keyLength)
        {
            _suite = suite;
            _pool = pool;
            _buffer = pool.Rent(bufferSizeNeeded);
            try
            {
                _handle = BCryptHelper.ImportKey(provider, _buffer.Memory, keyPointer, keyLength);
                _blockLength = BCryptPropertiesHelper.GetBlockLength(_handle);
            }
            catch
            {
                Dispose();
                throw;
            }
        }

        public int ExplicitNonceSize => 0;

        public byte[] HmacKey { set { _hmacKey = value; } }

        public int TrailerSize => _suite.Hash.HashLength;

        public unsafe void DecryptFrame(ReadableBuffer buffer, ref WritableBuffer writer)
        {
            var frameType = buffer.ReadBigEndian<TlsFrameType>();
            var newLength = buffer.Slice(3, 2).ReadBigEndian<ushort>() - _suite.Hash.HashLength - 16;
            var addInfo = new AdditionalInformation(_sequenceNumber, (ushort)newLength, frameType);
            _sequenceNumber++;
            buffer = buffer.Slice(5);
            var iv = buffer.Slice(0, 16).ToArray();
            buffer = buffer.Slice(16);
            if (buffer.IsSingleSpan)
            {
                writer.Ensure(newLength + _suite.Hash.HashLength);
                void* writePtr;
                writer.Memory.TryGetPointer(out writePtr);
                void* readPtr;
                buffer.First.TryGetPointer(out readPtr);
                fixed (void* ivPtr = iv)
                {
                    int result;
                    //BCRYPT_BLOCK_PADDING        0x00000001
                    ExceptionHelper.CheckReturnCode(
                        BCryptDecrypt(_handle, readPtr, newLength + _suite.Hash.HashLength, null, ivPtr, _blockLength, writePtr, newLength + _suite.Hash.HashLength, out result, 1));
                    writer.Advance(result - 1 - _suite.Hash.HashLength);
                }
            }
            else
            {
                throw new NotImplementedException();
            }
        }

        HmacCipherKey()
        {
            Dispose();
        }

        public void Dispose()
        {
            _handle?.Dispose();
            if (_buffer != null)
            {
                _pool.Return(_buffer);
                _buffer = null;
            }
            GC.SuppressFinalize(this);
        }

        public unsafe void Encrypt(ref WritableBuffer buffer, ReadableBuffer plainText, TlsFrameType frameType, IConnectionState state)
        {
            var bStart = buffer.BytesWritten;
            var hmac = _suite.Hash.GetLongRunningHash(_hmacKey);
            var addInfo = new AdditionalInformation(_sequenceNumber, (ushort)plainText.Length, frameType);
            hmac.HashData((byte*)&addInfo, sizeof(AdditionalInformation));
            hmac.HashData(plainText);
            var blocks = (int)Math.Ceiling((plainText.Length + hmac.HashLength + 1) / (double)_blockLength);
            var finalSize = blocks * _blockLength;
            var remainder = finalSize - plainText.Length - hmac.HashLength - 1;
            buffer.Ensure(finalSize);
            void* encryptStart;
            if (!buffer.Memory.TryGetPointer(out encryptStart))
            {
                throw new NotImplementedException();
            }
            buffer.Write(plainText.ToArray());
            void* ptr;
            if (!buffer.Memory.TryGetPointer(out ptr))
            {
                throw new NotImplementedException();
            }
            hmac.Finish((byte*)ptr, hmac.HashLength, true);
            buffer.Advance(hmac.HashLength);
            buffer.Write(Enumerable.Repeat((byte)remainder, remainder + 1).ToArray());
            fixed (void* ivptr = _iv)
            {
                int result;
                BCryptEncrypt(_handle, encryptStart, finalSize, null, ivptr, _iv.Length, encryptStart, finalSize, out result, 0);
            }
        }

        public void SetNonce(Span<byte> nounce)
        {
            throw new NotImplementedException();
        }

        public void WriteExplicitNonce(ref WritableBuffer buffer)
        {
            InteropRandom.GetRandom(_iv);
            buffer.Write(_iv);
        }
    }
}
