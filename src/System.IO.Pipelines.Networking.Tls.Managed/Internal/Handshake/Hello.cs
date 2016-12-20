using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Windows;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.TlsSpec;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Handshake
{
    internal static class Hello
    {
        public static void WriteServerHelloDone(ConnectionState state, ref WritableBuffer buffer)
        {
            var frame = new FrameWriter(ref buffer, TlsFrameType.Handshake, state);
            var handshakeFrame = new HandshakeWriter(ref buffer, state, HandshakeMessageType.ServerHelloDone);

            handshakeFrame.Finish(ref buffer);
            frame.Finish(ref buffer);
        }

        public static void ProcessClientHello(ReadableBuffer buffer, ConnectionState state)
        {
            var originalBuffer = buffer;
            buffer = buffer.Slice(4);

            if (buffer.ReadBigEndian<ushort>() != Tls12Utils.TLS_VERSION)
            {
                Alerts.AlertException.ThrowAlertException(Alerts.AlertType.Protocol_Version);
            }
            buffer = buffer.Slice(2);
            state.ClientRandom = buffer.Slice(0, Tls12Utils.RANDOM_LENGTH).ToArray();
            buffer = buffer.Slice(Tls12Utils.RANDOM_LENGTH);
            //Slice out session Id we don't care about it, and don't support it
            var sessionLength = buffer.ReadBigEndian<byte>();
            buffer = buffer.Slice(1);
            if (sessionLength > 0)
            {
                buffer = buffer.Slice(sessionLength);
            }
            buffer = buffer.Slice(state.GetCipherSuite(buffer));
            //Now we have the cipher suite we can start the handshake hash
            //this needs to be all messages upto the finish including this
            state.HandshakeHash.HashData(originalBuffer);
            
            //Compression Methods
            var numberOfCompressionMethods = buffer.ReadBigEndian<byte>();
            buffer = buffer.Slice(1);
            var compressionMethod = buffer.ReadBigEndian<byte>();
            if (compressionMethod != 0)
            {
                throw new NotSupportedException("Null compression is the only one currently supported");
            }
            buffer = buffer.Slice(numberOfCompressionMethods);
            state.ProcessHelloExtensions(buffer);
        }

        private static void ProcessHelloExtensions(this ConnectionState state, ReadableBuffer buffer)
        {
            var extensionsLength = buffer.ReadBigEndian<ushort>();
            buffer = buffer.Slice(2);
            if (extensionsLength != buffer.Length)
            {
                Alerts.AlertException.ThrowAlertException(Alerts.AlertType.Handshake_Failure);
            }
            while (buffer.Length > 0)
            {
                var extensionType = buffer.ReadBigEndian<ExtensionType>();
                buffer = buffer.Slice(2);
                var extensionSize = buffer.ReadBigEndian<ushort>();
                buffer = buffer.Slice(2);
                var extensionBuffer = buffer.Slice(0, extensionSize);
                buffer = buffer.Slice(extensionSize);
                switch (extensionType)
                {
                    case ExtensionType.Application_layer_protocol_negotiation:
                        //ExtensionAlpn(extensionBuffer);
                        break;
                    case ExtensionType.Supported_groups:
                         state.KeyExchange.ProcessSupportedGroupsExtension(extensionBuffer);
                        break;
                    case ExtensionType.Ec_point_formats:
                        state.KeyExchange.ProcessEcPointFormats(extensionBuffer);
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
        }

        private static int GetCipherSuite(this ConnectionState state, ReadableBuffer buffer)
        {
            //Deal with cipher suites
            var sizeOfCipherSuites = buffer.ReadBigEndian<ushort>();
            buffer = buffer.Slice(2, sizeOfCipherSuites);
            while (buffer.Length > 0)
            {
                var cipherId = buffer.ReadBigEndian<ushort>();
                var cipherInfo = state.CipherList.GetCipherInfo(cipherId);
                if (cipherInfo != null)
                {
                    state.SetCipherSuite(cipherInfo);
                    return sizeOfCipherSuites + 2;
                }
                buffer = buffer.Slice(2);
            }
            Alerts.AlertException.ThrowAlertException(Alerts.AlertType.Handshake_Failure);
            return sizeOfCipherSuites + 2;
        }

        public static void WriteServerHello(ref WritableBuffer buffer, ConnectionState state)
        {
            var frame = new FrameWriter(ref buffer, TlsFrameType.Handshake, state);
            var handshakeFrame = new HandshakeWriter(ref buffer, state, HandshakeMessageType.ServerHello);

            //Need to write the version + server random
            buffer.Ensure(Tls12Utils.RANDOM_LENGTH + 2);
            buffer.WriteBigEndian(Tls12Utils.TLS_VERSION);
            var memoryToFill = buffer.Memory.Slice(0, Tls12Utils.RANDOM_LENGTH);
            InteropRandom.GetRandom(memoryToFill);
            state.ServerRandom = memoryToFill.ToArray();
            buffer.Advance(32);
            //Write 0 for no session id at the moment
            buffer.Ensure(1);
            buffer.WriteBigEndian<byte>(0);
            //Write the ciphersuite, and compression method
            buffer.Ensure(3);
            buffer.WriteBigEndian(state.CipherSuite.CipherId);
            buffer.WriteBigEndian<byte>(0);
            //Do we want to write any extensions? lets reserve 2 bytes incase
            buffer.Ensure(2);
            var extensionLength = buffer.Memory.Slice(0, 2);
            var length = buffer.BytesWritten + 2;
            bool needToAdvance = true;
            needToAdvance = WriteAlpnExtension(needToAdvance, ref buffer, ApplicationLayerProtocolIds.None);
            if (needToAdvance == false)
            {
                //we wrote extenstions
                length = buffer.BytesWritten - length;
                extensionLength.Span.Write16BitNumber((ushort)length);
            }

            handshakeFrame.Finish(ref buffer);
            frame.Finish(ref buffer);
        }

        private static bool WriteAlpnExtension(bool needToAdvance, ref WritableBuffer buffer, ApplicationLayerProtocolIds protocolId)
        {
            return needToAdvance;
            //if (protocolId != ApplicationLayerProtocolIds.None)
            //{
            //    if (needToAdvance)
            //    {
            //        buffer.Advance(2);
            //    }
            //    buffer.WriteBigEndian((ushort)ExtensionType.Application_layer_protocol_negotiation);
            //    var protoBytes = ApplicationLayerProtocolExtension.AllProtocols[(int)Math.Log((int)protocolId, 2)];
            //    buffer.WriteBigEndian((ushort)(protoBytes.Length + 3));
            //    buffer.WriteBigEndian((ushort)(protoBytes.Length + 1));
            //    buffer.WriteBigEndian((byte)protoBytes.Length);
            //    buffer.Write(protoBytes);
            //    return false;
            //}
            //else
            //{
            //    return needToAdvance;
            //}
        }
    }
}
