using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Internal.ManagedTls;
using System.IO.Pipelines.Networking.Tls.Managed.Extensions;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Handshake
{
    public class HandshakeServerHelloWriter : IMessageWriter
    {
        public byte MessageType => (byte)HandshakeMessageType.ServerHello;

        public unsafe void WriteMessage(ref WritableBuffer buffer, ManagedConnectionContext context)
        {
            //Need to write the version + 32 bytes of random == 35 bytes
            buffer.Ensure(35);
            buffer.WriteBigEndian<ushort>(0x0303);
            var memoryToFill = buffer.Memory.Slice(0,32);
            InteropRandom.GetRandom(memoryToFill);
            context.SetServerRandom(memoryToFill);
            buffer.Advance(32);

            //Write 0 for no session id at the moment
            buffer.Ensure(1);
            buffer.WriteBigEndian<byte>(0);

            //Write the ciphersuite, and compression method
            buffer.Ensure(3);
            buffer.WriteBigEndian(context.CipherSuite.CipherId);
            buffer.WriteBigEndian<byte>(0);

            //Do we want to write any extensions? lets reserve 2 bytes incase
            buffer.Ensure(2);
            var extensionLength = buffer.Memory.Slice(0,2);
            var length = buffer.BytesWritten + 2;
            bool needToAdvance = true;
            needToAdvance = WriteAlpnExtension(needToAdvance, ref buffer, context);
            if(needToAdvance == false)
            {
                //we wrote extenstions
                length = buffer.BytesWritten - length;
                extensionLength.Span.Write16BitNumber((ushort)length);
            }
        }

        private static bool WriteAlpnExtension(bool needToAdvance, ref WritableBuffer buffer, ManagedConnectionContext context)
        {
            if(context.NegotiatedProtocol != ApplicationLayerProtocolIds.None)
            {
                if(needToAdvance)
                {
                    buffer.Advance(2);
                }
                buffer.WriteBigEndian((ushort)ExtensionType.Application_layer_protocol_negotiation);
                var protoBytes = ApplicationLayerProtocolExtension._allProtocols[(int)Math.Log((int)context.NegotiatedProtocol, 2)];
                buffer.WriteBigEndian((ushort)(protoBytes.Length + 3));
                buffer.WriteBigEndian((ushort)(protoBytes.Length + 1));
                buffer.WriteBigEndian((byte)protoBytes.Length);
                buffer.Write(protoBytes);
                return false;
            }
            else
            {
                return needToAdvance;
            }
        }
    }
}
