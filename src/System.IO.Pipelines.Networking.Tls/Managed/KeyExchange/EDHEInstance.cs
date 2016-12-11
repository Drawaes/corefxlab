using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Internal.ManagedTls;
using System.IO.Pipelines.Networking.Tls.Managed.Hash;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using static System.IO.Pipelines.Networking.Tls.Internal.ManagedTls.InteropPki;

namespace System.IO.Pipelines.Networking.Tls.Managed.KeyExchange
{
    public class EDHEInstance : IKeyExchangeInstance
    {
        private readonly IntPtr _key;
        private readonly ManagedConnectionContext _context;
        private string _selectedCurve;
        private EllipticCurves _curveType;
        private IntPtr _provider;
        private IntPtr _eKeyPair;
        private int _eKeySize;
        private const string BCRYPT_ECCPUBLIC_BLOB = "ECCPUBLICBLOB";

        public EDHEInstance(IntPtr key, ManagedConnectionContext context, IntPtr provider)
        {
            _context = context;
            _key = key;
            _provider = provider;
            InteropCurves.GetEccCurveNames(provider);
        }
        public void ProcessEcPointFormats(ReadableBuffer buffer)
        {

        }

        public void ProcessSupportedGroupsExtension(ReadableBuffer buffer)
        {
            buffer = buffer.Slice(2);
            while (buffer.Length > 0)
            {
                var value = (EllipticCurves)buffer.ReadBigEndian<ushort>();
                var name = InteropCurves.MapTlsCurve(value);
                if (name != null)
                {
                    _selectedCurve = name;
                    _curveType = value;
                    return;
                }
                buffer = buffer.Slice(2);
            }
            throw new InvalidOperationException("No matching curve found");
        }

        public unsafe void WriteServerKeyExchange(ref WritableBuffer buffer)
        {
            //Write header
            buffer.Ensure(9);
            buffer.WriteBigEndian((byte)TlsFrameType.Handshake);
            buffer.WriteBigEndian<ushort>(0x0303);
            var bookmark = buffer.Memory.Span;
            buffer.WriteBigEndian<ushort>(0);
            var amountWritten = buffer.BytesWritten;
            buffer.WriteBigEndian((byte)Handshake.HandshakeMessageType.ServerKeyExchange);
            var messageContentSize = buffer.Memory;
            var messageContentCurrentSize = buffer.BytesWritten + 3;
            buffer.WriteBigEndian<ushort>(0);
            buffer.WriteBigEndian<byte>(0);

            GenerateEphemeralKey();

            var hash = WriteServerECDHParams(ref buffer);
            
            buffer.Ensure(2);
            buffer.WriteBigEndian((byte)_context.CipherSuite.Hash.HashType);
            buffer.WriteBigEndian((byte)KeyExchangeType.RSA);

            var sigHash = ASN1HashHeader.Headers[(int)_context.CipherSuite.Hash.HashType].Concat(hash).ToArray();

            var rsaKeySize = InteropCertificates.GetSize(_key) / 8;

            var sig = new byte[rsaKeySize];

            Buffer.BlockCopy(sigHash, 0, sig, sig.Length - sigHash.Length, sigHash.Length);
            sig[0] = 0x00;
            sig[1] = 0x01;
            for (int i = 2; i < sig.Length - sigHash.Length - 1; i++)
            {
                sig[i] = 0xFF;
            }
            sig[sig.Length - sigHash.Length - 1] = 0x00;

            fixed (void* hashPtr = sig)
            {
                int result;
                Interop.CheckReturnOrThrow(
                    InteropCertificates.NCryptDecrypt(_key, hashPtr, sig.Length, null, hashPtr, sig.Length, out result, (uint)0));
            }
            buffer.Ensure(sig.Length + 2);
            buffer.WriteBigEndian((ushort)sig.Length);
            buffer.Write(new Span<byte>(sig));
            //buffer.Advance(sigsize);

            var messageContent = buffer.BytesWritten - messageContentCurrentSize;
            BufferExtensions.Write24BitNumber(messageContent, messageContentSize);

            var recordSize = buffer.BytesWritten - amountWritten;
            bookmark.Write16BitNumber((ushort)recordSize);

            var readableBuffer = buffer.AsReadableBuffer().Slice(5);
            _context.ClientFinishedHash.HashData(readableBuffer);
            _context.ServerFinishedHash.HashData(readableBuffer);
        }

        private unsafe byte[] WriteServerECDHParams(ref WritableBuffer buffer)
        {
            //Now we have the public key, throw away the first 8 bytes
            //Curve type
            var serverParamsSize = 5 + _eKeySize;
            buffer.Ensure(serverParamsSize);
            var bookMark = buffer.Memory;
            //Named curve
            buffer.WriteLittleEndian((byte)3);
            //Curve type
            buffer.WriteBigEndian((ushort)_curveType);
            //-------------------EC PARAMS WRITTEN

            buffer.WriteBigEndian((byte)(_eKeySize + 1));
            //Write compression type
            buffer.WriteBigEndian((byte)4);

            var keyBuffer = stackalloc byte[_eKeySize + 8];

            int resultSize;
            //Extract the public key
            Interop.CheckReturnOrThrow(
                InteropPki.BCryptExportKey(_eKeyPair, IntPtr.Zero, BCRYPT_ECCPUBLIC_BLOB, (IntPtr)keyBuffer, _eKeySize + 8, out resultSize, 0));

            var keySpan = new Span<byte>(keyBuffer + 8, _eKeySize);
            buffer.Write(keySpan);
            //-------------------Written Server ECHDE PARAMS

            var hash = _context.CipherSuite.Hash.GetLongRunningHash();
            hash.HashData(_context.RandomData.ToArray());
            hash.HashData(bookMark.Slice(0,serverParamsSize));
            return hash.Finish();
        }

        private void GenerateEphemeralKey()
        {
            //Step 1 generate a new key
            IntPtr ptr;
            Interop.CheckReturnOrThrow(
                Interop.BCryptGenerateKeyPair(_provider, out ptr, 0, 0));
            InteropCurves.SetEccCurveName(ptr, _selectedCurve);
            Interop.CheckReturnOrThrow(
                Interop.BCryptFinalizeKeyPair(ptr, 0));
            _eKeyPair = ptr;
            int keySize;
            Interop.CheckReturnOrThrow(
                InteropPki.BCryptExportKey(_eKeyPair, IntPtr.Zero, BCRYPT_ECCPUBLIC_BLOB, IntPtr.Zero, 0, out keySize, 0));
            _eKeySize = keySize - 8;
        }

        public void ProcessClientKeyExchange(ReadableBuffer buffer)
        {
            throw new NotImplementedException();
        }
    }
}
