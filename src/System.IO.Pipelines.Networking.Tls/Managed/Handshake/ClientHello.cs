using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Extensions;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Handshake
{
    public static class ClientHello
    {
        public static void ProcessClientHello(ReadableBuffer buffer, ManagedConnectionContext context)
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

            context.SetClientRandom(buffer.Slice(0, 32));
            buffer = buffer.Slice(32);

            var sessionLength = buffer.ReadBigEndian<byte>();
            buffer = buffer.Slice(1);
            byte[] sessionId = null;
            if (sessionLength > 0)
            {
                sessionId = buffer.Slice(0, sessionLength).ToArray();
                buffer = buffer.Slice(sessionLength);
            }

            var sizeOfCipherSuites = buffer.ReadBigEndian<ushort>();
            buffer = buffer.Slice(2);
            CipherSuite selectedCipher = GetCipher(buffer.Slice(0, sizeOfCipherSuites), context.SecurityContext.Ciphers);
            if (selectedCipher == null)
            {
                throw new NotSupportedException("No supported cipher suites");
            }
            context.SetCipherSuite(selectedCipher);
            context.HandshakeHash.HashData(originalBuffer);
            buffer = buffer.Slice(sizeOfCipherSuites);

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
            ProcessExtensions(buffer, context);
        }

        private static void ProcessExtensions(ReadableBuffer readBuffer, ManagedConnectionContext context)
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
                        ExtensionAlpn(context, extensionBuffer);
                        break;
                    case ExtensionType.Supported_groups:
                    case ExtensionType.SessionTicket:
                    case ExtensionType.Extended_master_secret:
                    case ExtensionType.Renegotiation_info:
                    case ExtensionType.Ec_point_formats:
                    case ExtensionType.Heartbeat:
                    case ExtensionType.Status_request:
                    case ExtensionType.Signed_certificate_timestamp:
                    case ExtensionType.Server_name:
                    case ExtensionType.Signature_algorithms:
                    default:
                        break;
                }
            }
        }

        private static void ExtensionAlpn(ManagedConnectionContext context, ReadableBuffer extensionBuffer)
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
                    if ((context.SecurityContext.AlpnSupportedProtocols & protoId) > 0)
                    {
                        context.NegotiatedProtocol = protoId;
                        break;
                    }
                }
                protosToCheck = protosToCheck.Slice(valToCheck.Length + 1);
            }
        }

        private static CipherSuite GetCipher(ReadableBuffer buffer, CipherList list)
        {
            while (buffer.Length > 0)
            {
                var cipherId = buffer.ReadBigEndian<ushort>();
                var cipherInfo = list.GetCipherInfo(cipherId);
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
