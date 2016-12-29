using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.TlsSpec;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Handshake
{
    internal static class Certificates
    {
        public static void WriteCertificate(ConnectionStateTls12 state, ref WritableBuffer buffer)
        {
            var frame = new FrameWriter(ref buffer, TlsFrameType.Handshake, state);
            var hw = new HandshakeWriter(ref buffer, state, HandshakeMessageType.Certificate);

            buffer.Ensure(6);
            BufferExtensions.Write24BitNumber(state.CipherSuite.KeyExchange.Certificate.RawData.Length + 3, ref buffer);
            BufferExtensions.Write24BitNumber(state.CipherSuite.KeyExchange.Certificate.RawData.Length, ref buffer);
            buffer.Ensure(state.CipherSuite.KeyExchange.Certificate.RawData.Length);
            buffer.Write(state.CipherSuite.KeyExchange.Certificate.RawData);

            hw.Finish(ref buffer);
            frame.Finish(ref buffer);
        }
    }
}
