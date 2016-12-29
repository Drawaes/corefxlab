using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Handshake;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Windows;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.TlsSpec;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Windows;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.KeyExchange.Windows
{
    internal class EcdheExchangeInstance:IKeyExchangeInstance
    {
        private readonly IConnectionState _state;
        private readonly EcdhExchangeProvider _exchangeProvider;
        private SafeBCryptAlgorithmHandle _provider;
        private EllipticCurves _curveType;
        private SafeBCryptKeyHandle _eKeyPair;
        private int _eKeySize;
        private IHashInstance _hashInstance;
        private CertificateType _certificateType;

        public EcdheExchangeInstance(IConnectionState state, EcdhExchangeProvider provider)
        {
            _state = state;
            _exchangeProvider = provider;
        }
        
        public void ProcessEcPointFormats(ReadableBuffer buffer)
        {
        }

        public void ProcessSupportedGroupsExtension(ReadableBuffer buffer)
        {
            var bufferTemp = buffer;
            buffer = buffer.Slice(2);
            while (buffer.Length > 1)
            {
                var value = (EllipticCurves)buffer.ReadBigEndian<ushort>();
                SafeBCryptAlgorithmHandle provider = _exchangeProvider.GetProvider(value);
                if (provider != null)
                {
                    _provider = provider;
                    _curveType = value;
                    return;
                }
                buffer = buffer.Slice(2);
            }
            Alerts.AlertException.ThrowAlertException(Alerts.AlertType.Handshake_Failure);
        }

        private void GenerateEphemeralKey()
        {
            _eKeyPair = BCryptSecretsHelper.GenerateKeyPair(_provider);
            _eKeySize = BCryptSecretsHelper.GetPublicKeyExportSize(_eKeyPair);
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
            using (var publicKeyHandle = BCryptSecretsHelper.ImportPublicKey(_provider, buffer, keyLength))
            {
                using (var secret = BCryptSecretsHelper.CreateSecret(publicKeyHandle, _eKeyPair))
                {
                    masterSecret = BCryptSecretsHelper.GenerateMasterSecret12(secret, _state.CipherSuite.Hash, _state.ClientRandom, _state.ServerRandom);
                }
            }
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

            BCryptSecretsHelper.ExportPublicKey(_eKeyPair, buffer.Memory.Slice(0, _eKeySize));
            buffer.Advance(_eKeySize);
            //-------------------Written Server ECHDE PARAMS
        }

        public unsafe void WriteServerKeyExchange(ref WritableBuffer buffer)
        {
            var frame = new FrameWriter(ref buffer, TlsFrameType.Handshake, _state);
            var hw = new HandshakeWriter(ref buffer, _state, HandshakeMessageType.ServerKeyExchange);

            GenerateEphemeralKey();

            //5 for the header
            var messageSize = 5 + _eKeySize;
            buffer.Ensure(messageSize);
            var bookMark = buffer.Memory;

            WriteServerECDHParams(ref buffer);

            var hash = _hashInstance;
            hash.HashData(_state.ClientRandom);
            hash.HashData(_state.ServerRandom);
            hash.HashData(bookMark.Slice(0, messageSize));

            buffer.Ensure(2);
            buffer.WriteBigEndian((byte)_state.CipherSuite.Hash.HashType);
            buffer.WriteBigEndian((byte)_certificateType);

            var hashResult = stackalloc byte[hash.HashLength];
            hash.Finish(hashResult, hash.HashLength, true);

            buffer.Ensure(hash.HashLength + 2);
            buffer.WriteBigEndian((ushort)hash.HashLength);

            buffer.Write(new Span<byte>(hashResult,hash.HashLength));
            
            hw.Finish(ref buffer);
            frame.Finish(ref buffer);
        }

        public void Dispose()
        {
            _eKeyPair?.Dispose();
            _hashInstance?.Dispose();
            GC.SuppressFinalize(this);
        }

        public void SetSignature(IHashInstance hashInstance, ICertificate certificateType)
        {
            _hashInstance = hashInstance;
            _certificateType = certificateType.CertificateType;
        }

        ~EcdheExchangeInstance()
        {
            Dispose();
        }
    }
}
