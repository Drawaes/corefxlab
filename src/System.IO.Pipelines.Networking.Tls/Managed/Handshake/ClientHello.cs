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
            buffer = buffer.Slice(1); // slice off the message type
            int contentSize = buffer.ReadBigEndian24bit();
            buffer = buffer.Slice(3);
            if(buffer.Length != contentSize)
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
            CipherInfo selectedCipher = GetCipher(buffer.Slice(0, sizeOfCipherSuites), context.Ciphers);
            if (selectedCipher == null)
            {
                throw new NotSupportedException("No supported cipher suites");
            }
            context.SetCipherSuite(selectedCipher);
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
            ProcessExtensions(buffer);
        }

        private static void ProcessExtensions(ReadableBuffer readBuffer)
        {
            while (readBuffer.Length > 0)
            {
                var extensionType = (ExtensionType)readBuffer.ReadBigEndian<ushort>();
                readBuffer = readBuffer.Slice(2);
                var extensionSize = readBuffer.ReadBigEndian<ushort>();
                readBuffer = readBuffer.Slice(2);

                switch (extensionType)
                {
                    case ExtensionType.Supported_groups:
                    case ExtensionType.SessionTicket:
                    case ExtensionType.Extended_master_secret:
                    case ExtensionType.Renegotiation_info:
                    case ExtensionType.Ec_point_formats:
                    case ExtensionType.Heartbeat:
                    case ExtensionType.Status_request:
                    case ExtensionType.Signed_certificate_timestamp:
                    case ExtensionType.Application_layer_protocol_negotiation:
                        readBuffer = readBuffer.Slice(extensionSize);
                        break;
                    case ExtensionType.Server_name:
                        //state.RequiresServerName = 1;
                        readBuffer = readBuffer.Slice(extensionSize);
                        break;
                    case ExtensionType.Signature_algorithms:
                        readBuffer = readBuffer.Slice(extensionSize);
                        break;
                    default:
                        readBuffer = readBuffer.Slice(extensionSize);
                        break;
                        //throw new NotImplementedException();
                }
            }
        }

        private static CipherInfo GetCipher(ReadableBuffer buffer, CipherList list)
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
