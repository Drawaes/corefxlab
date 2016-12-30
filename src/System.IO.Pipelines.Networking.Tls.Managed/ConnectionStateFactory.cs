using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.BulkCiphers;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Handshake;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.TlsSpec;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed
{
    internal class ConnectionStateFactory
    {
        private Pipe _inDataPipe;
        private IPipelineWriter _outDataPipe;
        private CipherList _cipherList;
        private IConnectionState _connectionState;
        private TlsVersions _tlsVersion;
        private ushort _actualVersion;

        internal ConnectionStateFactory(Pipe inDataPipe, IPipelineWriter outDataPipe, CipherList cipherList)
        {
            _cipherList = cipherList;
            _inDataPipe = inDataPipe;
            _outDataPipe = outDataPipe;
            DoHandshake();
        }

        public bool EncryptingServer => _connectionState?.EncryptingServer ?? false;
        public int MaxContentSize { get { return _connectionState.MaxContentSize; } }
        public byte[] ClientRandom { set { throw new NotImplementedException(); } }
        public IBulkCipherInstance ClientKey => _connectionState?.ClientKey;
        public IBulkCipherInstance ServerKey => _connectionState?.ServerKey;
        public IHashInstance HandshakeHash => _connectionState?.HandshakeHash;
        public IConnectionState ConnectionState => _connectionState;

        public void ProcessExtension(ExtensionType extensionType, ReadableBuffer buffer)
        {
        }

        public Task DecryptFrame(ReadableBuffer buffer, IPipelineWriter writer)
        {
            if (_connectionState == null)
            {
                //This can only be used for null ciphers at the initial handshake
                var output = writer.Alloc();
                output.Append(buffer.Slice(5));
                return output.FlushAsync();
            }
            return _connectionState.DecryptFrame(buffer, writer);
        }

        private async void DoHandshake()
        {
            while (true)
            {
                var result = await _inDataPipe.ReadAsync();
                var buffer = result.Buffer;
                try
                {
                    if (buffer.IsEmpty && result.IsCompleted)
                    {
                        break;
                    }
                    ReadableBuffer messageBuffer;
                    HandshakeMessageType messageType;
                    while (TryGetHandshakeType(ref buffer, out messageBuffer, out messageType))
                    {
                        if(_connectionState == null && messageType == HandshakeMessageType.ClientHello)
                        {
                            _connectionState = FindTlsVersion(messageBuffer);
                        }
                        if (_connectionState != null)
                        {
                            var writeBuffer = _outDataPipe.Alloc();
                            _connectionState.ProcessHandshakeMessage(messageBuffer, messageType, ref writeBuffer);
                            if(writeBuffer.BytesWritten > 0)
                            {
                                await writeBuffer.FlushAsync();
                            }
                            else
                            {
                                writeBuffer.Commit();
                            }
                            break;
                        }
                        Internal.Alerts.AlertException.ThrowAlertException(Internal.Alerts.AlertType.Unexpected_Message);
                    }
                }
                finally
                {
                    _inDataPipe.AdvanceReader(buffer.Start, buffer.End);
                }
            }
        }

        private IConnectionState FindTlsVersion(ReadableBuffer messageBuffer)
        {
            //We need to quickly decide which version of TLS we have and if we support it then hand off
            //Dump the handshake type, dump the length
            messageBuffer = messageBuffer.Slice(4);
            var version = messageBuffer.ReadBigEndian<ushort>();
            if (version < 0x0303)
            {
                //We don't support less than TLS 1.2 at the moment
                Internal.Alerts.AlertException.ThrowAlertException(Internal.Alerts.AlertType.Protocol_Version);
            }
            //It could be 1.2 or 1.3 we need to check for extensions so let's jump the data
            messageBuffer = messageBuffer.Slice(2);
            messageBuffer = messageBuffer.Slice(Tls12Utils.RANDOM_LENGTH);

            //Session Id is really a heritage concept so it has not been implemented
            var sessionLength = messageBuffer.ReadBigEndian<byte>();
            messageBuffer = messageBuffer.Slice(1);
            if (sessionLength > 0)
            {
                messageBuffer = messageBuffer.Slice(sessionLength);
            }
            //Slice out the cipher list we will not be processing yet
            var cipherListLength = messageBuffer.ReadBigEndian<ushort>();
            messageBuffer = messageBuffer.Slice(2 + cipherListLength);

            //Next is the compression methods, we only support null
            //However according to https://tlswg.github.io/tls13-spec/#rfc.section.4.1.2 if we get anything else
            //We MUST not connect with TLS 1.3
            var vectorLength = messageBuffer.ReadBigEndian<byte>();
            if (vectorLength != 1)
            {
                _tlsVersion = TlsVersions.Tls12;
            }
            var shouldBeNull = messageBuffer.Slice(1).ReadBigEndian<byte>();
            if (shouldBeNull != 0)
            {
                Internal.Alerts.AlertException.ThrowAlertException(Internal.Alerts.AlertType.Illegal_Parameter);
            }
            messageBuffer = messageBuffer.Slice(1 + vectorLength);
            //Should be in the extension zone no extensions no Tls 1.3
            if (messageBuffer.Length == 0)
            {
                _tlsVersion = TlsVersions.Tls12;
            }
            else if (_tlsVersion == TlsVersions.None)
            {
                //Still haven't made a decision so we need to take a look at the extensions
                var extensionLength = messageBuffer.ReadBigEndian<ushort>();
                var extensionBuffer = messageBuffer.Slice(2);
                if (extensionLength != extensionBuffer.Length)
                {
                    Internal.Alerts.AlertException.ThrowAlertException(Internal.Alerts.AlertType.Decode_Error);
                }
                ExtensionType eType;
                ReadableBuffer eBuffer;
                while (TryGetExtensionType(ref extensionBuffer, out eBuffer, out eType))
                {
                    if (eType == ExtensionType.Supported_Versions)
                    {
                        eBuffer = eBuffer.Slice(1);
                        while (eBuffer.Length > 1)
                        {
                            _actualVersion = eBuffer.ReadBigEndian<ushort>();
                            if ((_actualVersion & 0xff00) == 0x7f00)
                            {
                                //Tls 1.3 time
                                _tlsVersion = TlsVersions.Tls13;
                                break;
                            }
                            eBuffer = eBuffer.Slice(2);
                        }
                    }
                }
                if (_tlsVersion == TlsVersions.None)
                {
                    _tlsVersion = TlsVersions.Tls12;
                }
            }
            if (_tlsVersion == TlsVersions.Tls12)
            {
                return new ConnectionStateTls12(_cipherList);
            }
            if (_tlsVersion == TlsVersions.Tls13)
            {
                return new ConnectionStateTls13(_cipherList, _actualVersion);
            }
            //Couldn't find a valid protocol version
            Internal.Alerts.AlertException.ThrowAlertException(Internal.Alerts.AlertType.Protocol_Version);
            return null;

        }

        internal static bool TryGetExtensionType(ref ReadableBuffer buffer, out ReadableBuffer extensionBuffer, out ExtensionType extensionType)
        {
            if(buffer.Length == 0)
            {
                extensionType = default(ExtensionType);
                extensionBuffer = default(ReadableBuffer);
                return false;
            }
            if(buffer.Length < 4)
            {
                //We don't have a complete extension this is a bad message!
                Internal.Alerts.AlertException.ThrowAlertException(Internal.Alerts.AlertType.Decode_Error);
            }
            extensionType = buffer.ReadBigEndian<ExtensionType>();
            var length = buffer.Slice(2).ReadBigEndian<ushort>();
            buffer = buffer.Slice(4);
            if(buffer.Length < length)
            {
                //Again incomplete extension even if it is not one we care about
                Internal.Alerts.AlertException.ThrowAlertException(Internal.Alerts.AlertType.Decode_Error);
            }
            extensionBuffer = buffer.Slice(0, length);
            buffer = buffer.Slice(length);
            return true;
        }

        internal static bool TryGetHandshakeType(ref ReadableBuffer buffer, out ReadableBuffer messageBuffer, out HandshakeMessageType messageType)
        {
            if (buffer.Length < 4)
            {
                messageType = HandshakeMessageType.Incomplete;
                messageBuffer = default(ReadableBuffer);
                return false;
            }
            messageType = buffer.ReadBigEndian<HandshakeMessageType>();
            var length = buffer.Slice(1).ReadBigEndian24bit();
            if (buffer.Length < (length + 4))
            {
                messageBuffer = default(ReadableBuffer);
                return false;
            }
            messageBuffer = buffer.Slice(0, length + 4);
            buffer = buffer.Slice(messageBuffer.End);
            return true;
        }

        public Task ChangeCipher()
        {
           return _connectionState?.ChangeCipher();
        }
    }
}
