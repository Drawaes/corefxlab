using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Certificates;
using System.IO.Pipelines.Networking.Tls.Handshake;
using System.IO.Pipelines.Networking.Tls.Hashes;
using System.IO.Pipelines.Networking.Tls.Internal;
using System.IO.Pipelines.Networking.Tls.KeyExchange;
using System.IO.Pipelines.Networking.Tls.RecordProtocol;
using System.IO.Pipelines.Networking.Tls.TlsSpec;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Tls13
{
    public class Tls13StateMachine : IStateMachine
    {
        private TlsVersion _tlsVersion;
        private SecurePipelineConnection _connection;
        private CipherSuite _cipherSuite;
        private IHashInstance _handshakeHash;
        delegate void HandleMessageAction(ReadableBuffer buffer, ref WritableBuffer writer);
        private HandleMessageAction[] _stateTable = new HandleMessageAction[3];
        private const ushort FirstMessageValue = 0x15;
        private ISignatureInstance _signatureInstance;
        private IKeyExchangeInstance _keyExchangeInstance;
        private IRecordHandler _recordHandler;

        public Tls13StateMachine(TlsVersion version, SecurePipelineConnection connection, IRecordHandler recordHandler)
        {
            _recordHandler = recordHandler;
            _connection = connection;
            _tlsVersion = version;
            _stateTable[(ushort)RecordType.Handshake - FirstMessageValue] =
                (ReadableBuffer reader, ref WritableBuffer writer) =>
            {
                HandleClientHello(reader, ref writer);
                _handshakeHash.HashData(reader);
            };
        }

        public IHashInstance HandshakeHash => _handshakeHash;

        public void HandleRecord(RecordType recordType, ReadableBuffer buffer, ref WritableBuffer writer)
        {
            var actionIdx = (ushort)recordType - FirstMessageValue;
            if (actionIdx < 0 || actionIdx > 2 || _stateTable[actionIdx] == null)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.unexpected_message);
            }
            _stateTable[actionIdx](buffer, ref writer);
        }

        private void HandleClientHello(ReadableBuffer buffer, ref WritableBuffer writer)
        {
            var length = buffer.Slice(1).ReadBigEndian24bit();
            if (buffer.Length != (4 + length))
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error);
            }
            buffer = buffer.Slice(4);
            var version = buffer.ReadBigEndian<TlsVersion>();
            buffer = buffer.Slice(sizeof(TlsVersion));
            //We just generally skip everything in 1.3 except the cipher list
            buffer = buffer.Slice(TlsConsts.RandomLength);
            //Slice SessionId
            BufferExtensions.SliceVector<byte>(ref buffer);
            //Slice Cipher Suite
            var ciphers = BufferExtensions.SliceVector<ushort>(ref buffer);
            while (ciphers.Length > 1)
            {
                var cipherCode = ciphers.ReadBigEndian<ushort>();
                ciphers = ciphers.Slice(sizeof(ushort));
                if (_connection.Listener.CipherList.TryGetCipherSuite(cipherCode, _tlsVersion, out _cipherSuite))
                {
                    break;
                }
                else
                {
                    _cipherSuite = null;
                }
            }
            if (_cipherSuite == null)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.handshake_failure);
            }
            _handshakeHash = _cipherSuite.GetHashInstance();
            //Skip compression
            BufferExtensions.SliceVector<byte>(ref buffer);
            var allExtensions = BufferExtensions.SliceVector<ushort>(ref buffer);

            while (allExtensions.Length > 0)
            {
                ExtensionType extType;
                allExtensions = allExtensions.ReadAndSliceBigEndian(out extType);
                var extBuffer = BufferExtensions.SliceVector<ushort>(ref allExtensions);

                switch (extType)
                {
                    case ExtensionType.signature_algorithms:
                        ProcessSignatureAlgorithmsExtensions(extBuffer);
                        break;
                    case ExtensionType.key_share:
                        ProcessKeyShareExtension(extBuffer);
                        break;
                    case ExtensionType.supported_groups:
                        ProcessSupportedGroupsExtension(extBuffer);
                        break;
                }
            }
            if (_signatureInstance == null || _keyExchangeInstance == null)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.illegal_parameter);
            }
            //Check that we have enough state to move on or if we need to close down, or maybe just try for a new negotiation
            if (_keyExchangeInstance.HasClientKey)
            {
                WriteServerHello(ref writer);
                return;
            }
            _recordHandler.WriteRecord(ref writer, RecordType.Handshake,
                     (ref WritableBuffer write) =>
                     HandshakeWriter.WriteHandshake(ref write, this, HandshakeType.hello_retry_request, WriteHelloRetryRequest));
        }

        private void WriteServerHello(ref WritableBuffer writer)
        {
            throw new NotImplementedException();
        }

        private void WriteHelloRetryRequest(ref WritableBuffer writer)
        {
            writer.WriteBigEndian(_tlsVersion);
            writer.WriteBigEndian((ushort)6);
            writer.WriteBigEndian(ExtensionType.key_share);
            writer.WriteBigEndian((ushort)2);
            writer.WriteBigEndian(_keyExchangeInstance.NamedGroup);
        }

        private void ProcessSupportedGroupsExtension(ReadableBuffer extBuffer)
        {
            if (_keyExchangeInstance != null)
            {
                return;
            }
            extBuffer = BufferExtensions.SliceVector<ushort>(ref extBuffer);
            while (extBuffer.Length > 1)
            {
                NamedGroup group;
                extBuffer = extBuffer.ReadAndSliceBigEndian(out group);
                _keyExchangeInstance = _connection.Listener.CipherList.KeyExchangeProvider.GetInstance(group);
                if (_keyExchangeInstance != null)
                {
                    break;
                }
            }
            if (_keyExchangeInstance == null)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.illegal_parameter);
            }
        }

        private void ProcessSignatureAlgorithmsExtensions(ReadableBuffer extBuffer)
        {
            if (_signatureInstance != null)
            {
                return;
            }
            extBuffer = BufferExtensions.SliceVector<ushort>(ref extBuffer);
            while (extBuffer.Length > 1)
            {
                SignatureScheme sigType;
                extBuffer = extBuffer.ReadAndSliceBigEndian(out sigType);
                _signatureInstance = _connection.Listener.CertificateList.GetSignatureInstance(sigType, _connection.Listener.CipherList.HashProvider);
                if (_signatureInstance != null)
                {
                    break;
                }
            }
            if (_signatureInstance == null)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.unsupported_certificate);
            }
        }

        private void ProcessKeyShareExtension(ReadableBuffer extBuffer)
        {
            extBuffer = BufferExtensions.SliceVector<ushort>(ref extBuffer);
            while (extBuffer.Length > 1)
            {
                NamedGroup group;
                extBuffer = extBuffer.ReadAndSliceBigEndian(out group);
                _keyExchangeInstance = _connection.Listener.CipherList.KeyExchangeProvider.GetInstance(group, BufferExtensions.SliceVector<ushort>(ref extBuffer));
                if (_keyExchangeInstance != null)
                {
                    break;
                }
            }
        }
    }
}
