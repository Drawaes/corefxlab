using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Handshake;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.KeyExchange;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed
{
    internal class ConnectionState
    {
        private CipherSuite _currentSuite;
        private bool _handshakeComplete;
        private bool _changedCipherSpec;
        private byte[] _clientRandom = new byte[32];
        private byte[] _serverRandom = new byte[32];
        private ManagedSecurityContext _securityContext;
        private HashInstance _handshakeHash;
        private IKeyExchangeInstance _keyExchange;
        private SecureManagedPipeline _managedPipeline;
        private bool _serverDataEncrypted;
        private bool _clientDataEncrypted;
        
        public ConnectionState(ManagedSecurityContext securityContext, SecureManagedPipeline managedPipeline)
        {
            _managedPipeline = managedPipeline;
            _securityContext = securityContext;
        }

        public bool ServerDataEncrypted => _serverDataEncrypted;
        public HashInstance HandshakeHash => _handshakeHash;
        public byte[] ServerRandom => _serverRandom;
        public byte[] ClientRandom => _clientRandom;
        public CipherSuite CipherSuite => _currentSuite;
        public SecureManagedPipeline Pipe => _managedPipeline;
        public ICertificate Certificate => _securityContext.Certificate;
        
        public void CheckForValidFrameType(TlsFrameType frameType)
        {
            switch(frameType)
            {
                case TlsFrameType.Invalid:
                case TlsFrameType.Incomplete:
                case TlsFrameType.Alert:
                    throw new InvalidOperationException("Bad frame");
                case TlsFrameType.AppData:
                    if(!_handshakeComplete)
                    {
                        throw new InvalidOperationException("Data cannot be received before we switch to encrypted mode");
                    }
                    break;
                case TlsFrameType.Handshake:
                    if(_handshakeComplete)
                    {
                        throw new InvalidOperationException("We don't support renegotiation at this time");
                    }
                    break;
                case TlsFrameType.ChangeCipherSpec:
                default:
                    throw new NotImplementedException("Get around to this!");

            }
        }

        public void DecryptRecord(ref ReadableBuffer buffer)
        {
            if(!_changedCipherSpec)
            {
                //Do nothing the buffer is just fine the way it is we aren't decrypting yet
                return;
            }

            throw new NotImplementedException("No decryption yet!");
        }

        internal Task ProcessHandshakeAsync(ReadableBuffer messageBuffer, IPipelineWriter output)
        {
            var handshakeType = messageBuffer.ReadBigEndian<HandshakeMessageType>();

            switch(handshakeType)
            {
                case HandshakeMessageType.ClientHello:
                    ProcessClientHello(messageBuffer);
                    var writeBuffer = output.Alloc();
                    ServerHello.Write(ref writeBuffer, this);
                    writeBuffer.Commit();
                    writeBuffer = output.Alloc();
                    ServerCertificate.Write(ref writeBuffer, this);
                    writeBuffer.Commit();
                    writeBuffer = output.Alloc(); 
                    _keyExchange.WriteServerKeyExchange(ref writeBuffer);
                    writeBuffer.Commit();
                    writeBuffer = output.Alloc();
                    ServerHelloDone.Write(ref writeBuffer, this);
                    return writeBuffer.FlushAsync();
                case HandshakeMessageType.ClientKeyExchange:

                default:
                    throw new NotImplementedException();      
            }
            throw new NotImplementedException();
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
                        _managedPipeline.NegotiatedProtocol = protoId;
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
    }
}
