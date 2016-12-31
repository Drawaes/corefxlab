using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Internal;
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

        public Tls13StateMachine(TlsVersion version, SecurePipelineConnection connection)
        {
            _connection = connection;
            _tlsVersion = version;
            _stateTable[(ushort)RecordType.Handshake - FirstMessageValue] = 
                (ReadableBuffer reader,  ref WritableBuffer writer) =>
            {
                HandleClientHello(reader);
                _handshakeHash.HashData(reader);
            };
        }
        
        public void HandleRecord(RecordType recordType, ReadableBuffer buffer, ref WritableBuffer writer)
        {
            var actionIdx = (ushort)recordType - FirstMessageValue;
            if(actionIdx < 0 || actionIdx > 2 || _stateTable[actionIdx] == null)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.unexpected_message);
            }
            _stateTable[actionIdx](buffer, ref writer);
        }

        private void HandleClientHello(ReadableBuffer buffer)
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

            while(allExtensions.Length > 0)
            {
                ExtensionType extType;
                allExtensions = allExtensions.ReadAndSliceBigEndian(out extType);
                var extBuffer = BufferExtensions.SliceVector<ushort>(ref allExtensions);

                switch(extType)
                {
                    case ExtensionType.signature_algorithms:
                        throw new NotImplementedException();
                    case ExtensionType.key_share:
                        throw new NotImplementedException();
                    case ExtensionType.supported_groups:
                        throw new NotImplementedException();
                }
            }
        }
    }
}
