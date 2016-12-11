using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Internal.ManagedTls;
using System.IO.Pipelines.Networking.Tls.Managed.Hash;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
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
        private int _keyLengthInBits = 2048;

        public DHEInstance(IntPtr key, ManagedConnectionContext context, IntPtr provider)
        {
            _context = context;
            _signKey = key;
            _provider = provider;
        }
        public void ProcessEcPointFormats(ReadableBuffer buffer)
        {
            //Curves are not needed for classic DH
        }

        public void ProcessSupportedGroupsExtension(ReadableBuffer buffer)
        {
            //Curves are not needed for classic DH
        }

        public unsafe void WriteServerKeyExchange(ref WritableBuffer buffer)
        {
            //Generate key
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
            
            int size;
            Interop.CheckReturnOrThrow(InteropPki.BCryptExportKey(keyHandle, IntPtr.Zero, InteropPki.BCRYPT_DH_PUBLIC_BLOB, IntPtr.Zero, 0, out size, 0));

            var keyBuffer = stackalloc byte[size];
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

            var hash = _context.CipherSuite.Hash.GetLongRunningHash();
            hash.HashData(_context.RandomData.ToArray());
            hash.HashData(bookmark.Slice(0,(2 + keySizeBytes) * 3).ToArray());
            var finished = hash.Finish();

            finished = ASN1HashHeader.Headers[(int)_context.CipherSuite.Hash.HashType].Concat(finished).ToArray();

            buffer.Ensure(2);
            buffer.WriteBigEndian((byte) _context.CipherSuite.Hash.HashType);
            buffer.WriteBigEndian((byte) KeyExchangeType.RSA);

            int sigsize;
            var padding = new InteropPki.BCRYPT_PKCS1_PADDING_INFO();
            //padding.pszAlgId = _context.CipherSuite.Hash.HashType.ToString();

            var providers = InteropTls.Providers;

            fixed (void* hashPtr = finished)
            {
                //Interop.CheckReturnOrThrow(
                //    InteropPki.NCryptSignHash(_signKey, ref padding, (IntPtr)hashPtr, _context.CipherSuite.Hash.BlockLength, IntPtr.Zero, 0, out sigsize, InteropPki.Padding.BCRYPT_PAD_PKCS1));
                ////InteropTls.SslSignHash(_signKey,(IntPtr)hashPtr, _context.CipherSuite.Hash.BlockLength, IntPtr.Zero,0,out sigsize));
                //buffer.Ensure(sigsize+2);
                //buffer.WriteBigEndian((ushort)sigsize);
                //void* sigPtr;
                //buffer.Memory.TryGetPointer(out sigPtr);
                //Interop.CheckReturnOrThrow(
                //    InteropPki.NCryptSignHash(_signKey, ref padding, (IntPtr)hashPtr, _context.CipherSuite.Hash.BlockLength, (IntPtr)sigPtr, sigsize, out sigsize, InteropPki.Padding.BCRYPT_PAD_PKCS1));
                    //InteropTls.SslSignHash(_signKey, (IntPtr)hashPtr, _context.CipherSuite.Hash.BlockLength, (IntPtr)sigPtr,sigsize, out sigsize));
            }
            //buffer.Advance(sigsize);

            var messageContent = buffer.BytesWritten - messageContentCurrentSize;
            BufferExtensions.Write24BitNumber(messageContent, messageContentSize);

            var recordSize = buffer.BytesWritten - amountWritten;
            bookmark.Write16BitNumber((ushort)recordSize);
        }

        public void ProcessClientKeyExchange(ReadableBuffer buffer)
        {
            throw new NotImplementedException();
        }
    }
}
