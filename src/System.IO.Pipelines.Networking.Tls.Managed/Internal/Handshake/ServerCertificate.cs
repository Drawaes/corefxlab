using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Handshake
{
    internal static class ServerCertificate
    {
        public static void Write(ref WritableBuffer buffer, ConnectionState state)
        {
            var fw = new FrameWriter(ref buffer, TlsFrameType.Handshake);
            var hw = new HandshakeWriter(ref buffer, state, HandshakeMessageType.Certificate);

            buffer.Ensure(6);
            BufferExtensions.Write24BitNumber(state.Certificate.RawData.Length + 3, ref buffer);
            BufferExtensions.Write24BitNumber(state.Certificate.RawData.Length, ref buffer);
            buffer.Ensure(state.Certificate.RawData.Length);
            buffer.Write(new ReadOnlySpan<byte>(state.Certificate.RawData));

            hw.Finish(buffer);
            fw.Finish(buffer);
        }
    }
}
