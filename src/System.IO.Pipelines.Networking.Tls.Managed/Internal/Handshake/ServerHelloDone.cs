using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Handshake
{
    internal static class ServerHelloDone
    {
        public static void Write(ref WritableBuffer buffer,ConnectionState state)
        {
            var frame = new FrameWriter(ref buffer, TlsFrameType.Handshake);
            var handshakeFrame = new HandshakeWriter(ref buffer, state, HandshakeMessageType.ServerHelloDone);

            handshakeFrame.Finish(buffer);
            frame.Finish(buffer);
        }
    }
}
