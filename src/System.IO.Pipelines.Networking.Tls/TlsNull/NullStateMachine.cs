using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.IO.Pipelines.Networking.Tls.Internal;
using System.IO.Pipelines.Networking.Tls.TlsSpec;
using System.IO.Pipelines.Networking.Tls.RecordProtocol;

namespace System.IO.Pipelines.Networking.Tls.TlsNull
{
    public class NullStateMachine : IStateMachine
    {
        private SecurePipelineConnection _connection;

        public NullStateMachine(SecurePipelineConnection connection)
        {
            _connection = connection;
        }
                
        private static TlsVersion FindVersion(ReadableBuffer buffer)
        {
            var length = buffer.Slice(1).ReadBigEndian24bit();
            if (buffer.Length != (4 + length))
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error);
            }
            buffer = buffer.Slice(4);
            var version = buffer.ReadBigEndian<TlsVersion>();
            buffer = buffer.Slice(sizeof(TlsVersion));
            if (version != TlsVersion.Tls12)
            {
                //We don't support lower versions at the moment
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.protocol_version);
            }
            //Due to the way Tls 1.3 does backwards compatibility we need to jump to the end and find the extensions
            buffer = buffer.Slice(TlsConsts.RandomLength);
            //Slice SessionId
            BufferExtensions.SliceVector<byte>(ref buffer);
            //Slice Cipher Suite
            BufferExtensions.SliceVector<ushort>(ref buffer);
            //Slice Compression Method
            BufferExtensions.SliceVector<byte>(ref buffer);
            if(buffer.Length == 0)
            {
                return TlsVersion.Tls12;
            }
            var extensionBuffer = BufferExtensions.SliceVector<ushort>(ref buffer);
            if(buffer.Length > 0)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error);
            }
            while(extensionBuffer.Length > 0)
            {
                var extType = extensionBuffer.ReadBigEndian<ExtensionType>();
                extensionBuffer = extensionBuffer.Slice(sizeof(ExtensionType));
                var currentExt = BufferExtensions.SliceVector<ushort>(ref extensionBuffer);
                if (extType != ExtensionType.supported_versions)
                {
                    continue;
                }
                var versions = BufferExtensions.SliceVector<byte>(ref currentExt);
                while(versions.Length > 1)
                {
                    version = versions.ReadBigEndian<TlsVersion>();
                    if(version == TlsVersion.Tls13 || version == TlsVersion.Tls13Draft18)
                    {
                        return version;
                    }
                    versions = versions.Slice(sizeof(TlsVersion));
                }
            }
            return TlsVersion.Tls12;
        }

        public void HandleRecord(RecordType recordType, ReadableBuffer buffer, ref WritableBuffer writer)
        {
            if(recordType != RecordType.Handshake)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal,Alerts.AlertDescription.unexpected_message);
            }
            var version = FindVersion(buffer);
            IStateMachine statemachine;
            IRecordHandler recordHandler;
            switch (version)
            {
                case TlsVersion.Tls13Draft18:
                case TlsVersion.Tls13:
                    statemachine = new Tls13.Tls13StateMachine(version, _connection);
                    recordHandler = new Tls13RecordHandler();
                    break;
                case TlsVersion.Tls12:
                    throw new NotImplementedException();
                default:
                    Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.protocol_version);
                    return;
            }
            _connection.StateMachine = statemachine;
            _connection.RecordHandler = recordHandler;
            statemachine.HandleRecord(recordType, buffer, ref writer);
        }
    }
}
