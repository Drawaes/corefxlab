using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.BulkCiphers;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Handshake;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.KeyExchange;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.TlsSpec;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal
{
    internal class ConnectionStateTls12 : IConnectionState
    {
        private bool _decryptingClient;
        private bool _encryptingServer;
        private TaskCompletionSource<bool> _clientCipherSpecChanged = new TaskCompletionSource<bool>();
        private TaskCompletionSource<bool> _keysCreated = new TaskCompletionSource<bool>();
        private Task _cipherMode;
        private CipherSuite _cipherSuite;
        private readonly CipherList _cipherList;
        private IKeyExchangeInstance _keyExchange;
        private byte[] _masterSecret;

        public ConnectionStateTls12(CipherList cipherList)
        {
            _cipherList = cipherList;
            _cipherMode = Task.WhenAll(_clientCipherSpecChanged.Task, _keysCreated.Task);
        }

        public byte[] ClientRandom { get; set; }
        public byte[] ServerRandom { get; set; }
        public IBulkCipherInstance ClientKey { get; set; }
        public IBulkCipherInstance ServerKey { get; set; }
        public IHashInstance HandshakeHash { get; set; }
        internal CipherList CipherList => _cipherList;
        internal IKeyExchangeInstance KeyExchange => _keyExchange;
        public CipherSuite CipherSuite => _cipherSuite;
        public bool EncryptingServer => _encryptingServer;
        public int MaxContentSize => 16 * 1024 - 1 - ServerKey.TrailerSize - ServerKey.ExplicitNonceSize - 5;
        public TlsVersions TlsVersion => TlsVersions.Tls12;

        public bool TrySetCipherSuite(ushort cipherSuite)
        {
            var cs = _cipherList.GetCipherInfo(cipherSuite);
            if (cs == null || cs.TlsVersion != TlsVersions.Tls12)
            {
                return false;
            }
            _cipherSuite = cs;
            HandshakeHash = _cipherSuite.Hash.GetLongRunningHash(null);
            _keyExchange = _cipherSuite.KeyExchange.GetInstance(this);
            return true;
        }

        public void ProcessExtension(ExtensionType extensionType, ReadableBuffer buffer)
        {
            switch (extensionType)
            {
                case ExtensionType.Application_layer_protocol_negotiation:
                case ExtensionType.Supported_groups:
                    KeyExchange.ProcessSupportedGroupsExtension(buffer);
                    break;
                case ExtensionType.Ec_point_formats:
                    KeyExchange.ProcessEcPointFormats(buffer);
                    break;
                case ExtensionType.Heartbeat:
                case ExtensionType.SessionTicket:
                case ExtensionType.Extended_master_secret:
                case ExtensionType.Renegotiation_info:
                case ExtensionType.Status_request:
                case ExtensionType.Signed_certificate_timestamp:
                case ExtensionType.Server_name:
                case ExtensionType.Signature_algorithms:
                default:
                    break;
            }
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

        private unsafe void GenerateKeys()
        {
            //We have the master secret we can move on to making our keys!!!
            var seed = new byte[ClientRandom.Length + ServerRandom.Length + Tls12Utils.KeyExpansionSize];
            var seedSpan = new Span<byte>(seed);
            var seedLabel = new Span<byte>((byte*)Tls12Utils.KeyExpansionPointer, Tls12Utils.KeyExpansionSize);
            seedLabel.CopyTo(seedSpan);
            seedSpan = seedSpan.Slice(seedLabel.Length);

            var serverRandom = new Span<byte>(ServerRandom);
            serverRandom.CopyTo(seedSpan);
            seedSpan = seedSpan.Slice(serverRandom.Length);
            var clientRandom = new Span<byte>(ClientRandom);
            clientRandom.CopyTo(seedSpan);

            var keyMaterial = new byte[CipherSuite.KeyMaterialRequired];
            Tls12Utils.P_Hash12(CipherSuite.Hash, keyMaterial, _masterSecret, seed);
            CipherSuite.ProcessKeyMaterial(this, keyMaterial);
        }

        public Task ChangeCipher()
        {
            _clientCipherSpecChanged.SetResult(true);
            return _cipherMode;
        }

        public void ProcessHandshakeMessage(ReadableBuffer messageBuffer, HandshakeMessageType messageType, ref WritableBuffer writeBuffer)
        {
            //Check current state is okay with the current type
            switch(messageType)
            {
                case HandshakeMessageType.ClientHello:
                    Hello.ProcessClientHello(messageBuffer, this);
                    Hello.WriteServerHello(ref writeBuffer, this);
                    Handshake.Certificates.WriteCertificate(this, ref writeBuffer);
                    _keyExchange.WriteServerKeyExchange(ref writeBuffer);
                    Hello.WriteServerHelloDone(this, ref writeBuffer);
                    break;
                case HandshakeMessageType.ClientKeyExchange:
                    _masterSecret = _keyExchange.ProcessClientKeyExchange(messageBuffer);
                    GenerateKeys();
                    _decryptingClient = true;
                    _keysCreated.SetResult(true);
                    break;
                case HandshakeMessageType.Finished:
                    Finished.ProcessClient(messageBuffer, this, _masterSecret);
                    ChangeCipherSpec.Write(this, ref writeBuffer);
                    _encryptingServer = true;
                    Finished.WriteServer(ref writeBuffer, this, _masterSecret);
                    break;
                default:
                    throw new NotImplementedException();
            }
        }
    }
}
