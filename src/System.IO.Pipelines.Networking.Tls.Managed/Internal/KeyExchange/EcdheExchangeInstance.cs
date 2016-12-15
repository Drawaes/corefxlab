using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Handshake;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.KeyGeneration;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Windows;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.KeyExchange
{
    internal class EcdheExchangeInstance : IKeyExchangeInstance
    {
        private readonly ICertificate _certificate;
        private readonly ConnectionState _state;
        private readonly EcdhExchangeProvider _exchangeProvider;
        private IntPtr _provider;
        private EllipticCurves _curveType;
        private IntPtr _eKeyPair;
        private int _eKeySize;

        public EcdheExchangeInstance(ICertificate certificate, ConnectionState state, EcdhExchangeProvider provider)
        {
            _certificate = certificate;
            _state = state;
            _exchangeProvider = provider;
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
                IntPtr provider = _exchangeProvider.GetProvider(value);
                if (provider != IntPtr.Zero)
                {
                    _provider = provider;
                    _curveType = value;
                    return;
                }
                buffer = buffer.Slice(2);
            }
            throw new InvalidOperationException("No matching curve found");
        }

        private void GenerateEphemeralKey()
        {
            _eKeyPair = InteropSecrets.GenerateKeyPair(_provider);
            _eKeySize = InteropSecrets.GetPublicKeyExportSize(_eKeyPair);
        }

        public unsafe void WriteServerKeyExchange(ref WritableBuffer buffer)
        {
            var fw = new FrameWriter(ref buffer, TlsFrameType.Handshake, _state);
            var hw = new HandshakeWriter(ref buffer, _state, HandshakeMessageType.ServerKeyExchange);

            GenerateEphemeralKey();

            //5 for the header
            var messageSize = 5 + _eKeySize;
            buffer.Ensure(messageSize);
            var bookMark = buffer.Memory;

            WriteServerECDHParams(ref buffer);

            var hash = _state.CipherSuite.Hash.GetLongRunningHash();
            hash.HashData(_state.ClientRandom);
            hash.HashData(_state.ServerRandom);
            hash.HashData(bookMark.Slice(0,messageSize));

            buffer.Ensure(2);
            buffer.WriteBigEndian((byte)_state.CipherSuite.Hash.HashType);
            buffer.WriteBigEndian((byte)_state.Certificate.CertificateType);

            var hashResult = stackalloc byte[hash.HashSize];
            hash.Finish(hashResult,hash.HashSize,true);

            buffer.Ensure(_certificate.SignatureSize + 2);
            buffer.WriteBigEndian((ushort)_certificate.SignatureSize);

            _certificate.SignHash(_state.CipherSuite.Hash, buffer.Memory.Slice(0,_certificate.SignatureSize), hashResult, hash.HashSize);
            buffer.Advance(_certificate.SignatureSize);

            hw.Finish(buffer);
            fw.Finish(ref buffer);
        }

        public unsafe byte[] ProcessClientKeyExchange(ReadableBuffer buffer)
        {
            _state.HandshakeHash.HashData(buffer);
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
                throw new IndexOutOfRangeException("Bad length or compression type");
            }

            byte[] masterSecret;
            var publicKeyHandle = InteropSecrets.ImportPublicKey(_provider, buffer, keyLength);
            try
            {
                var secret = InteropSecrets.CreateSecret(publicKeyHandle, _eKeyPair);
                try
                {
                    masterSecret = InteropSecrets.GenerateMasterSecret12(secret, _state.CipherSuite.Hash, _state.ClientRandom, _state.ServerRandom);
                }
                finally
                {
                    InteropSecrets.DestroySecret(secret);
                }
            }
            finally
            {
                InteropSecrets.DestroyPublicKey(publicKeyHandle);
            }
            //We have the master secret we can move on to making our keys!!!
            var seed = new byte[_state.ClientRandom.Length + _state.ServerRandom.Length + TlsLabels.KeyExpansionSize];
            var seedSpan = new Span<byte>(seed);
            var seedLabel = new Span<byte>((byte*)TlsLabels.KeyExpansion, TlsLabels.KeyExpansionSize);
            seedLabel.CopyTo(seedSpan);
            seedSpan = seedSpan.Slice(seedLabel.Length);

            var serverRandom = new Span<byte>(_state.ServerRandom);
            serverRandom.CopyTo(seedSpan);
            seedSpan = seedSpan.Slice(serverRandom.Length);
            var clientRandom = new Span<byte>(_state.ClientRandom);
            clientRandom.CopyTo(seedSpan);

            var keyMaterial = new byte[_state.CipherSuite.KeyMaterialRequired];
            PseudoRandomFunctions.P_Hash12(_state.CipherSuite.Hmac, keyMaterial , masterSecret, seed);
            _state.CipherSuite.ProcessKeyMaterial(_state, keyMaterial);
            return masterSecret;
        }

        private unsafe void WriteServerECDHParams(ref WritableBuffer buffer)
        {
            //Named curve
            buffer.WriteLittleEndian((byte)3);
            //Curve type
            buffer.WriteBigEndian((ushort)_curveType);
            //-------------------EC PARAMS WRITTEN

            buffer.WriteBigEndian((byte)(_eKeySize + 1));
            //Write compression type
            buffer.WriteBigEndian((byte)4);

            InteropSecrets.ExportPublicKey(_eKeyPair, buffer.Memory.Slice(0, _eKeySize));
            buffer.Advance(_eKeySize);
            //-------------------Written Server ECHDE PARAMS
        }
    }
}
