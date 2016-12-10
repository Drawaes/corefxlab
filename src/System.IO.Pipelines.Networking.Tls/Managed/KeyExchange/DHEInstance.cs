using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Internal.ManagedTls;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.KeyExchange
{
    public class DHEInstance : IKeyExchangeInstance
    {
        private readonly IntPtr _signKey;
        private IntPtr _generatedKey;
        private readonly ManagedConnectionContext _context;
        private string _selectedCurve;
        private IntPtr _provider;
        private NativeBufferPool _pool;
        private int _keyLengthInBits = 2048;

        public DHEInstance(IntPtr key, ManagedConnectionContext context, IntPtr provider, NativeBufferPool pool)
        {
            _context = context;
            _signKey = key;
            _provider = provider;
            _pool = pool;
        }
        public void ProcessEcPointFormats(ReadableBuffer buffer)
        {
            throw new NotImplementedException();
        }

        public void ProcessSupportedGroupsExtension(ReadableBuffer buffer)
        {
            //Curves are not needed for classic DH
            return;
        }

        public unsafe void WriteServerKeyExchange(ref WritableBuffer buffer)
        {
            IntPtr keyHandle;
            Interop.CheckReturnOrThrow(Interop.BCryptGenerateKeyPair(_provider, out keyHandle, _keyLengthInBits, 0));
            Interop.CheckReturnOrThrow(Interop.BCryptFinalizeKeyPair(keyHandle, 0));
            _generatedKey = keyHandle;
            buffer.Ensure(5);
            buffer.WriteBigEndian((byte)TlsFrameType.Handshake);
            buffer.WriteBigEndian<ushort>(0x0303);
            var bookmark = buffer.Memory.Span;
            buffer.Advance(2);
            var amountWritten = buffer.BytesWritten;
            buffer.WriteBigEndian((byte)Handshake.HandshakeMessageType.ServerKeyExchange);
            var messageContentSize = buffer.Memory;
            var messageContentCurrentSize = buffer.BytesWritten + 3;
            buffer.WriteBigEndian<ushort>(0);
            buffer.WriteBigEndian<byte>(0);

            buffer.Write(_context.ClientRandom);

            uint size;
            Interop.CheckReturnOrThrow(InteropPki.BCryptExportKey(keyHandle, IntPtr.Zero, InteropPki.BCRYPT_DH_PUBLIC_BLOB, IntPtr.Zero, 0, out size, 0));

            var keyBuffer = stackalloc byte[(int)size];
            Interop.CheckReturnOrThrow(InteropPki.BCryptExportKey(keyHandle, IntPtr.Zero, InteropPki.BCRYPT_DH_PUBLIC_BLOB, (IntPtr)keyBuffer, (int)size, out size, 0));

            //Reference https://tools.ietf.org/html/rfc5246#section-7.4.3
            //Header is a magic number + key length, we know the key length already
            size = size -8;
            keyBuffer += 8;
            var keySizeBytes = _keyLengthInBits / 8;
            var keySpan = new Span<byte>(keyBuffer,keySizeBytes * 3);
            
            buffer.Ensure((2 + keySizeBytes) * 3);
            var bookmarkStartOfServerParams = buffer.Memory;
            void* bookMarkPtr;
            bookmarkStartOfServerParams.TryGetPointer(out bookMarkPtr);
            buffer.WriteBigEndian((ushort)(keySizeBytes));
            buffer.Write(keySpan.Slice(0,keySizeBytes));
            keySpan = keySpan.Slice(keySizeBytes);
            buffer.WriteBigEndian((ushort)keySizeBytes);
            buffer.Write(keySpan.Slice(0,keySizeBytes));
            keySpan = keySpan.Slice(keySizeBytes);
            buffer.WriteBigEndian((ushort)keySizeBytes);
            buffer.Write(keySpan);

            var hash = stackalloc byte[_context.CipherSuite.Hash.BlockLength];
            _context.CipherSuite.Hash.HashValue(hash, _context.CipherSuite.Hash.BlockLength,null,0,(byte*)bookMarkPtr, (2 + keySizeBytes) * 3);

            buffer.Ensure(2);
            buffer.WriteBigEndian((byte) _context.CipherSuite.Hash.HashType);
            buffer.WriteBigEndian((byte) KeyExchangeType.RSA);


            throw new NotImplementedException();
        }

    }
}
