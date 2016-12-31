using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.BulkCiphers;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Handshake;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.KeyExchange;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.TlsSpec;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal
{
    internal class ConnectionStateTls13 : IConnectionState
    {
        private readonly CipherList _cipherList;
        private Pipe _inDataPipe;
        private IPipelineWriter _outDataPipe;
        private CipherSuite _cipherSuite;
        private bool _encryptingServer;
        private bool _decryptingClient;
        private IHashInstance _certificate;
        private HashType _signatureHashType;
        private ITls13KeyExchangeInstance _keyExchangeInstance;
        private TlsVersions _tlsVersion = TlsVersions.Tls1;
        private ushort _actualVersion;

        public ConnectionStateTls13(CipherList cipherList, ushort tlsVersion)
        {
            _actualVersion = tlsVersion;
            _cipherList = cipherList;
        }

        public IBulkCipherInstance ClientKey { get { throw new NotImplementedException(); } }
        public IBulkCipherInstance ServerKey { get { throw new NotImplementedException(); } }
        public byte[] ClientRandom { get; set; }
        public byte[] ServerRandom { get; set; }
        public IHashInstance HandshakeHash { get; set; }
        public CipherSuite CipherSuite => _cipherSuite;
        public bool EncryptingServer => _encryptingServer;
        public int MaxContentSize => 16 * 1024 - 1 - ServerKey.TrailerSize - ServerKey.ExplicitNonceSize - 5;
        public TlsVersions TlsVersion => _tlsVersion;

        public bool TrySetCipherSuite(ushort cipherSuite)
        {
            if(_cipherSuite != null)
            {
                return true;
            }
            var cs = _cipherList.GetCipherInfo(cipherSuite);
            if (cs == null || cs.TlsVersion != TlsVersions.Tls13)
            {
                return false;
            }
            _cipherSuite = cs;
            HandshakeHash = _cipherSuite.Hash.GetLongRunningHash(null);
            return true;
        }

        public void ProcessExtension(ExtensionType extensionType, ReadableBuffer buffer)
        {
            ushort length;
            switch (extensionType)
            {
                case ExtensionType.Supported_groups:
                    if(_keyExchangeInstance != null)
                    {
                        //We have a pre arranged key exchange so we can jump out
                        break;
                    }
                    length = buffer.ReadBigEndian<ushort>();
                    buffer = buffer.Slice(2);
                    while(buffer.Length > 1)
                    {
                        var group = buffer.ReadBigEndian<NamedGroup>();
                        _keyExchangeInstance = _cipherList.KeyFactory.GetKeyExchangeInstance(group);
                        if(_keyExchangeInstance != null)
                        {
                            break;
                        }
                        buffer = buffer.Slice(2);
                    }
                    break;
                case ExtensionType.Signature_algorithms:
                    SignatureAlgorithmExtension(buffer);
                    break;
                case ExtensionType.Key_Share:
                    length = buffer.ReadBigEndian<ushort>();
                    buffer = buffer.Slice(2);
                    while (buffer.Length > 1)
                    {
                        var group = buffer.ReadBigEndian<NamedGroup>();
                        buffer = buffer.Slice(2);
                        length = buffer.ReadBigEndian<ushort>();
                        buffer = buffer.Slice(2);
                        _keyExchangeInstance = _cipherList.KeyFactory.GetKeyExchangeInstance(group);
                        if (_keyExchangeInstance != null)
                        {
                            _keyExchangeInstance.SetClientKey(buffer.Slice(0,length));
                            break;
                        }
                        buffer = buffer.Slice(length);
                    }
                    break;
            }
        }

        private void SignatureAlgorithmExtension(ReadableBuffer buffer)
        {
            var length = buffer.ReadBigEndian<ushort>();
            buffer = buffer.Slice(2);
            while (buffer.Length > 1)
            {
                var sigType = buffer.ReadBigEndian<SignatureScheme>();
                _certificate = _cipherList.CertificateFactory.TryGetCertificateInstance(sigType);
                if (_certificate != null)
                {
                    break;
                }
                buffer = buffer.Slice(2);
            }
            if (_certificate == null)
            {
                Alerts.AlertException.ThrowAlertException(Alerts.AlertType.Handshake_Failure);
            }
        }
        
        public Task ChangeCipher()
        {
            throw new NotImplementedException();
        }

        public Task DecryptFrame(ReadableBuffer buffer, IPipelineWriter writer)
        {
            var output = writer.Alloc();
            if (_decryptingClient)
            {

                ClientKey.DecryptFrame(buffer, ref output);
            }
            else
            {
                output.Append(buffer.Slice(5));
            }
            return output.FlushAsync();
        }

        public void ProcessHandshakeMessage(ReadableBuffer messageBuffer, HandshakeMessageType messageType, ref WritableBuffer outBuffer)
        {
            switch (messageType)
            {
                case HandshakeMessageType.ClientHello:
                    Hello.ProcessClientHello(messageBuffer, this);
                    if(_keyExchangeInstance == null)
                    {
                        Alerts.AlertException.ThrowAlertException(Alerts.AlertType.Handshake_Failure);
                    }
                    else if(_keyExchangeInstance.HasClientKey)
                    {
                        var fw = new FrameWriter(ref outBuffer, TlsFrameType.Handshake, this);
                        var hw = new HandshakeWriter(ref outBuffer, this, HandshakeMessageType.ServerHello);

                        outBuffer.Ensure(4 + Tls12Utils.RANDOM_LENGTH);
                        outBuffer.WriteBigEndian(_actualVersion);
                        Interop.Windows.InteropRandom.GetRandom(outBuffer.Memory.Slice(0,Tls12Utils.RANDOM_LENGTH));
                        outBuffer.Advance(Tls12Utils.RANDOM_LENGTH);
                        outBuffer.WriteBigEndian(_cipherSuite.CipherId);

                        //Extensions length, + extension type + extension length +
                        var totalLength = 8 + 97 ;
                        outBuffer.Ensure(totalLength + 2);
                        outBuffer.WriteBigEndian((ushort)totalLength);
                        outBuffer.WriteBigEndian(ExtensionType.Key_Share);
                        totalLength -= 4;
                        outBuffer.WriteBigEndian((ushort)totalLength);

                        outBuffer.WriteBigEndian(_keyExchangeInstance.Group);
                        outBuffer.WriteBigEndian((ushort)( _keyExchangeInstance.KeySize + 1));
                        _keyExchangeInstance.GetPublicKey(ref outBuffer);

                        hw.Finish(ref outBuffer);
                        fw.Finish(ref outBuffer);
                        _keyExchangeInstance.GenerateTrafficKeys(this);
                    }
                    else
                    {
                        //We don't have enough agreed key information so we need to send a Hello_Retry_Request
                        var fw = new FrameWriter(ref outBuffer, TlsFrameType.Handshake, this);
                        var hw = new HandshakeWriter(ref outBuffer, this, HandshakeMessageType.Hello_Retry_Request);

                        outBuffer.WriteBigEndian(_actualVersion);
                        outBuffer.WriteBigEndian((ushort)6);
                        outBuffer.WriteBigEndian(ExtensionType.Key_Share);
                        outBuffer.WriteBigEndian((ushort)2);
                        outBuffer.WriteBigEndian(_keyExchangeInstance.Group);

                        hw.Finish(ref outBuffer);
                        fw.Finish(ref outBuffer);
                    }
                    break;
                default:
                    throw new NotImplementedException();
            }
        }
    }
}
