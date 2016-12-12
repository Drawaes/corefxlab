﻿using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Internal.ManagedTls;
using System.IO.Pipelines.Networking.Tls.Managed.Handshake;
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
        private EdhKeyExchange _providerFactory;
        private IntPtr _eKeyPair;
        private int _eKeySize;
        private IntPtr _provider;
        private const string BCRYPT_ECCPUBLIC_BLOB = "ECCPUBLICBLOB";

        public EDHEInstance(IntPtr key, ManagedConnectionContext context, EdhKeyExchange providerFactory)
        {
            _context = context;
            _key = key;
            _providerFactory = providerFactory;
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
            buffer.WriteBigEndian((byte)HandshakeMessageType.ServerKeyExchange);
            var messageContentSize = buffer.Memory;
            var messageContentCurrentSize = buffer.BytesWritten + 3;
            buffer.WriteBigEndian<ushort>(0);
            buffer.WriteBigEndian<byte>(0);

            GenerateEphemeralKey();
            var hash = WriteServerECDHParams(ref buffer);

            buffer.Ensure(2);
            buffer.WriteBigEndian((byte)_context.CipherSuite.Hash.HashType);
            buffer.WriteBigEndian((byte)KeyExchangeType.RSA);
                        
            fixed(void* inPtr = hash)
            {
                var paddInfo = new BCRYPT_PKCS1_PADDING_INFO();
                paddInfo.pszAlgId = Marshal.StringToHGlobalUni(_context.CipherSuite.Hash.HashType.ToString() + "\0");

                int result;
                Interop.CheckReturnOrThrow(
                    InteropCertificates.NCryptSignHash(_key, &paddInfo,(IntPtr)inPtr, hash.Length, IntPtr.Zero, 0, out result, InteropCertificates.Padding.NCRYPT_PAD_PKCS1_FLAG ));
                
                buffer.Ensure(result + 2);
                buffer.WriteBigEndian((ushort)result);
                void* ptr;
                if(!buffer.Memory.TryGetPointer(out ptr))
                {
                    throw new InvalidOperationException();
                }
                Interop.CheckReturnOrThrow(
                    InteropCertificates.NCryptSignHash(_key, &paddInfo, (IntPtr)inPtr, hash.Length, (IntPtr)ptr, result, out result, InteropCertificates.Padding.NCRYPT_PAD_PKCS1_FLAG));
                buffer.Advance(result);
            }

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
            hash.HashData(bookMark.Slice(0, serverParamsSize));
            return hash.Finish();
        }

        private void GenerateEphemeralKey()
        {
            //get the provider for the named key
            _provider = _providerFactory.GetProvider(_selectedCurve);

            //generate a new key
            IntPtr ptr;
            Interop.CheckReturnOrThrow(
                Interop.BCryptGenerateKeyPair(_provider, out ptr, 0, 0));
            Interop.CheckReturnOrThrow(
                Interop.BCryptFinalizeKeyPair(ptr, 0));
            _eKeyPair = ptr;
            int keySize;
            Interop.CheckReturnOrThrow(
                BCryptExportKey(_eKeyPair, IntPtr.Zero, BCRYPT_ECCPUBLIC_BLOB, IntPtr.Zero, 0, out keySize, 0));
            _eKeySize = keySize - 8;
        }

        public unsafe void ProcessClientKeyExchange(ReadableBuffer buffer)
        {
            _context.ClientFinishedHash.HashData(buffer);
            _context.ServerFinishedHash.HashData(buffer);

            buffer = buffer.Slice(1); // Slice off type
            uint contentSize = buffer.ReadBigEndian<ushort>();
            buffer = buffer.Slice(2);
            contentSize = (contentSize << 8) + buffer.ReadBigEndian<byte>();
            buffer = buffer.Slice(1);

            if (buffer.Length != contentSize)
            {
                throw new IndexOutOfRangeException($"The message buffer contains the wrong amount of data for our operation");
            }
            
            var keyLength = buffer.ReadBigEndian<byte>();
            keyLength--;
            buffer = buffer.Slice(1);
            var compressionType = buffer.ReadBigEndian<byte>();
            buffer = buffer.Slice(1, buffer.End);
            if (buffer.Length != keyLength || compressionType != 4)
            {
                throw new Alerts.AlertException(Alerts.AlertDescription.Descriptions[50], Alerts.AlertServerity.Fatal);
            }

            //Now we have the point and can load the key
            var keyBuffer = stackalloc byte[keyLength + 8];
            var blobHeader = new InteropStructs.BCRYPT_ECCKEY_BLOB();
            //BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC    0x504B4345
            blobHeader.dwMagic = 0x504B4345;
            blobHeader.cbKey = keyLength / 2;
            Marshal.StructureToPtr(blobHeader, (IntPtr)keyBuffer, false);
            buffer.CopyTo(new Span<byte>(keyBuffer + 8, keyLength));

            IntPtr keyHandle;
            Interop.CheckReturnOrThrow(
                BCryptImportKeyPair(_provider, IntPtr.Zero, BCRYPT_ECCPUBLIC_BLOB, out keyHandle, (IntPtr)keyBuffer, keyLength + 8, 0));

            IntPtr secretHandle;
            Interop.CheckReturnOrThrow(
                InteropSecrets.BCryptSecretAgreement(_eKeyPair, keyHandle, out secretHandle, 0));

            InteropSecrets.CalculateMasterSecret(secretHandle, _context.SeedBuffer.ToArray());

            throw new NotImplementedException();
        }
    }
}
