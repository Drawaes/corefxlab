using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.BulkCipher;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Handshake;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.KeyExchange;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed
{
    internal class ConnectionState : ISecureContext
    {
        private CipherSuite _currentSuite;
        private bool _handshakeComplete;
        private byte[] _clientRandom = new byte[32];
        private byte[] _serverRandom = new byte[32];
        private ManagedSecurityContext _securityContext;
        private HashInstance _handshakeHash;
        private IKeyExchangeInstance _keyExchange;
        private bool _serverDataEncrypted;
        private bool _clientDataEncrypted;
        private static readonly Task s_cachedTask = Task.FromResult(0);
        private byte[] _masterSecret;

        public ConnectionState(ManagedSecurityContext securityContext)
        {
            _securityContext = securityContext;
        }

        public bool ServerDataEncrypted => _serverDataEncrypted;
        public bool ClientDataEncrypted { internal set { _clientDataEncrypted = value; } get { return _clientDataEncrypted; } }
        public HashInstance HandshakeHash => _handshakeHash;
        public byte[] ServerRandom => _serverRandom;
        public byte[] ClientRandom => _clientRandom;
        public CipherSuite CipherSuite => _currentSuite;
        public ICertificate Certificate => _securityContext.Certificate;
        internal BulkCipherInstance ClientKey { get; set; }
        internal BulkCipherInstance ServerKey { get; set; }
        internal bool HashshakeComplete => _handshakeComplete;

        public int BlockSize => 1026 * 16 - 1 - 16 - 8;

        public int TrailerSize { get; set; }

        public int HeaderSize { get; set; }

        public bool ReadyToSend => _handshakeComplete;

        public ApplicationLayerProtocolIds NegotiatedProtocol => ApplicationLayerProtocolIds.None;

        public bool IsServer => true;

        public CipherInfo CipherInfo => new CipherInfo() { KeySizeInBits = CipherSuite.BulkCipher.KeySizeInBytes * 8, Name = CipherSuite.CipherString };

        public void CheckForValidFrameType(TlsFrameType frameType)
        {
            switch (frameType)
            {
                case TlsFrameType.Invalid:
                case TlsFrameType.Incomplete:
                    throw new InvalidOperationException("Bad frame");
                case TlsFrameType.AppData:
                    if (!_handshakeComplete)
                    {
                        throw new InvalidOperationException("Data cannot be received before we switch to encrypted mode");
                    }
                    break;
                case TlsFrameType.Handshake:
                    if (_handshakeComplete)
                    {
                        throw new InvalidOperationException("We don't support renegotiation at this time");
                    }
                    break;
                case TlsFrameType.ChangeCipherSpec:
                    if (ClientKey == null || ServerKey == null)
                    {
                        throw new InvalidOperationException("Tried to change cipher spec when bulk keys were not setup");
                    }
                    break;
                case TlsFrameType.Alert:
                    break;
                default:
                    throw new NotImplementedException("Get around to this!");

            }
        }

        public void DecryptRecord(ref ReadableBuffer buffer)
        {
            if (_clientDataEncrypted)
            {
                ClientKey.DecryptFrame(ref buffer);
            }
            buffer = buffer.Slice(5);
        }

        private Task ProcessClientFinished(ReadableBuffer messageBuffer, IPipelineWriter output)
        {
            Finished.ProcessClient(messageBuffer, this, _masterSecret);
            var writeBuffer = output.Alloc();
            ChangeCipherSpec.Write(ref writeBuffer, this);
            _serverDataEncrypted = true;
            Finished.WriteServer(ref writeBuffer, this, _masterSecret);
            _handshakeComplete = true;
            return writeBuffer.FlushAsync();
        }

        private Task HandleClientHello(ReadableBuffer messageBuffer, IPipelineWriter output)
        {
            ProcessClientHello(messageBuffer);
            var writeBuffer = output.Alloc();
            ServerHello.Write(ref writeBuffer, this);
            ServerCertificate.Write(ref writeBuffer, this);
            _keyExchange.WriteServerKeyExchange(ref writeBuffer);
            ServerHelloDone.Write(ref writeBuffer, this);
            return writeBuffer.FlushAsync();
        }

        private void ProcessClientHello(ReadableBuffer buffer)
        {
            var originalBuffer = buffer;
            buffer = buffer.Slice(1); // slice off the message type
            int contentSize = buffer.ReadBigEndian24bit();
            buffer = buffer.Slice(3);
            if (buffer.Length != contentSize)
            {
                throw new ArgumentOutOfRangeException("Content length doesn't match the amount of data we have");
            }
            var protocolVersion = buffer.ReadBigEndian<ushort>();
            buffer = buffer.Slice(2);
            if (protocolVersion != 0x0303)
            {
                throw new InvalidOperationException("Wrong protocol version");
            }
            //Slice out client random
            buffer.Slice(0, _clientRandom.Length).CopyTo(_clientRandom);
            buffer = buffer.Slice(_clientRandom.Length);
            //Slice out session Id we don't care about it, and don't support it
            var sessionLength = buffer.ReadBigEndian<byte>();
            buffer = buffer.Slice(1);
            if (sessionLength > 0)
            {
                buffer = buffer.Slice(sessionLength);
            }
            //Deal with cipher suites
            var sizeOfCipherSuites = buffer.ReadBigEndian<ushort>();
            buffer = buffer.Slice(2);
            CipherSuite selectedCipher = GetCipher(buffer.Slice(0, sizeOfCipherSuites));
            if (selectedCipher == null)
            {
                throw new NotSupportedException("No supported cipher suites");
            }
            _currentSuite = selectedCipher;
            _handshakeHash = _currentSuite.Hash.GetLongRunningHash();
            _handshakeHash.HashData(originalBuffer);
            _keyExchange = _currentSuite.KeyExchange.GetInstance(this);
            buffer = buffer.Slice(sizeOfCipherSuites);
            //Compression Methods
            var numberOfCompressionMethods = buffer.ReadBigEndian<byte>();
            buffer = buffer.Slice(1);
            var compressionMethod = buffer.ReadBigEndian<byte>();
            if (compressionMethod != 0)
            {
                throw new NotSupportedException("Null compression is the only one currently supported");
            }
            buffer = buffer.Slice(numberOfCompressionMethods);

            //We are into extension zone!
            var extensionsLength = buffer.ReadBigEndian<ushort>();
            buffer = buffer.Slice(2);
            if (extensionsLength != buffer.Length)
            {
                throw new IndexOutOfRangeException("When processing the extensions found an incorrect length");
            }
            ProcessExtensions(buffer);
        }

        private void ProcessExtensions(ReadableBuffer readBuffer)
        {
            while (readBuffer.Length > 0)
            {
                var extensionType = (ExtensionType)readBuffer.ReadBigEndian<ushort>();
                readBuffer = readBuffer.Slice(2);
                var extensionSize = readBuffer.ReadBigEndian<ushort>();
                readBuffer = readBuffer.Slice(2);
                var extensionBuffer = readBuffer.Slice(0, extensionSize);
                readBuffer = readBuffer.Slice(extensionSize);

                switch (extensionType)
                {
                    case ExtensionType.Application_layer_protocol_negotiation:
                        ExtensionAlpn(extensionBuffer);
                        break;
                    case ExtensionType.Supported_groups:
                        _keyExchange.ProcessSupportedGroupsExtension(extensionBuffer);
                        break;
                    case ExtensionType.SessionTicket:
                    case ExtensionType.Extended_master_secret:
                    case ExtensionType.Renegotiation_info:
                    case ExtensionType.Ec_point_formats:
                        _keyExchange.ProcessEcPointFormats(extensionBuffer);
                        break;
                    case ExtensionType.Heartbeat:
                    case ExtensionType.Status_request:
                    case ExtensionType.Signed_certificate_timestamp:
                    case ExtensionType.Server_name:
                    case ExtensionType.Signature_algorithms:
                        //ExtensionSignature(extensionBuffer);
                        break;
                    default:
                        break;
                }
            }
        }

        private void ExtensionAlpn(ReadableBuffer extensionBuffer)
        {
            Span<byte> protosToCheck;
            if (extensionBuffer.IsSingleSpan)
            {
                protosToCheck = extensionBuffer.First.Span;
            }
            else
            {
                protosToCheck = new Span<byte>(extensionBuffer.ToArray());
            }
            protosToCheck = protosToCheck.Slice(2);
            while (protosToCheck.Length > 0)
            {
                ApplicationLayerProtocolIds protoId;
                var valToCheck = protosToCheck.Slice(1, protosToCheck.Read<byte>());
                if (ApplicationLayerProtocolExtension.TryGetNegotiatedProtocol(valToCheck, out protoId))
                {
                    if ((_securityContext.AlpnSupportedProtocols & protoId) > 0)
                    {
                        //_managedPipeline.NegotiatedProtocol = protoId;
                        break;
                    }
                }
                protosToCheck = protosToCheck.Slice(valToCheck.Length + 1);
            }
        }

        private CipherSuite GetCipher(ReadableBuffer buffer)
        {
            while (buffer.Length > 0)
            {
                var cipherId = buffer.ReadBigEndian<ushort>();
                var cipherInfo = _securityContext.CipherList.GetCipherInfo(cipherId);
                if (cipherInfo != null)
                {
                    return cipherInfo;
                }
                buffer = buffer.Slice(2);
            }
            return null;
        }

        public void Dispose()
        {
            if (_clientRandom != null)
            {
                for (int i = 0; i < _clientRandom.Length; i++)
                {
                    _clientRandom[i] = 0;
                    if (_serverRandom != null)
                    {
                        _serverRandom[i] = 0;
                    }
                }
            }
            _currentSuite = null;
            _handshakeComplete = false;
            _handshakeHash?.Dispose();
            _handshakeHash = null;
            _keyExchange?.Dispose();
            _keyExchange = null;
            if (_masterSecret != null)
            {
                for (int i = 0; i < _masterSecret.Length; i++)
                {
                    _masterSecret[i] = 0;
                }
            }
            ServerKey.Dispose();
            ClientKey.Dispose();
            GC.SuppressFinalize(this);
        }

        public Task ProcessContextMessageAsync(ReadableBuffer readBuffer, IPipelineWriter writer)
        {
            var frameType = readBuffer.ReadBigEndian<TlsFrameType>();
            CheckForValidFrameType(frameType);
            DecryptRecord(ref readBuffer);

            if (frameType == TlsFrameType.Handshake)
            {

                var handshakeType = readBuffer.ReadBigEndian<HandshakeMessageType>();

                switch (handshakeType)
                {
                    case HandshakeMessageType.ClientHello:
                        return HandleClientHello(readBuffer, writer);
                    case HandshakeMessageType.ClientKeyExchange:
                        _masterSecret = _keyExchange.ProcessClientKeyExchange(readBuffer);
                        return s_cachedTask;
                    case HandshakeMessageType.Finished:
                        return ProcessClientFinished(readBuffer, writer);
                    default:
                        throw new NotImplementedException();
                }
            }
            else if (frameType == TlsFrameType.ChangeCipherSpec)
            {
                ClientDataEncrypted = true;
                return s_cachedTask;
            }
            throw new NotImplementedException();
        }

        public Task ProcessContextMessageAsync(IPipelineWriter writer)
        {
            return s_cachedTask;
        }

        public Task DecryptAsync(ReadableBuffer encryptedData, IPipelineWriter decryptedPipeline)
        {
            DecryptRecord(ref encryptedData);
            var buffer = decryptedPipeline.Alloc();
            buffer.Append(encryptedData);
            return buffer.FlushAsync();
        }

        public Task EncryptAsync(ReadableBuffer unencryptedData, IPipelineWriter encryptedPipeline)
        {
            var buffer = encryptedPipeline.Alloc();
            buffer.Ensure(5);
            buffer.WriteBigEndian(TlsFrameType.AppData);
            buffer.WriteBigEndian<ushort>(0x0303);
            var bookmark = buffer.Memory;
            buffer.Advance(2);
            var amountWritten = buffer.BytesWritten;

            ServerKey.Encrypt(ref buffer, unencryptedData, TlsFrameType.AppData);

            var recordSize = buffer.BytesWritten - amountWritten;
            bookmark.Span.Write((ushort)((recordSize >> 8) | (recordSize << 8)));
            return buffer.FlushAsync();
        }

        ~ConnectionState()
        {
            Dispose();
        }
    }
}
