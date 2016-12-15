using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Windows;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Handshake
{
    internal static class ServerHello
    {
        public static void Write(ref WritableBuffer buffer, ConnectionState state)
        {
            var frame = new FrameWriter(ref buffer, TlsFrameType.Handshake, state);
            var handshakeFrame = new HandshakeWriter(ref buffer, state, HandshakeMessageType.ServerHello);

            //Need to write the version + server random
            buffer.Ensure(state.ServerRandom.Length + 2);
            buffer.WriteBigEndian<ushort>(0x0303);
            var memoryToFill = buffer.Memory.Slice(0, 32);
            InteropRandom.GetRandom(memoryToFill);
            memoryToFill.CopyTo(new Span<byte>(state.ServerRandom));
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
            needToAdvance = WriteAlpnExtension(needToAdvance, ref buffer, state.Pipe);
            if (needToAdvance == false)
            {
                //we wrote extenstions
                length = buffer.BytesWritten - length;
                extensionLength.Span.Write16BitNumber((ushort)length);
            }

            handshakeFrame.Finish(buffer);
            frame.Finish(ref buffer);
        }

        private static bool WriteAlpnExtension(bool needToAdvance, ref WritableBuffer buffer, SecureManagedPipeline pipe)
        {
            if (pipe.NegotiatedProtocol != ApplicationLayerProtocolIds.None)
            {
                if (needToAdvance)
                {
                    buffer.Advance(2);
                }
                buffer.WriteBigEndian((ushort)ExtensionType.Application_layer_protocol_negotiation);
                var protoBytes = ApplicationLayerProtocolExtension.AllProtocols[(int)Math.Log((int)pipe.NegotiatedProtocol, 2)];
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
