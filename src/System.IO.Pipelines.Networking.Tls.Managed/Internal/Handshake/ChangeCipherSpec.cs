using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.TlsSpec;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Handshake
{
    internal static class ChangeCipherSpec
    {
        public static void Write(ConnectionState state, ref WritableBuffer buffer)
        {
            var frame = new FrameWriter(ref buffer, TlsFrameType.ChangeCipherSpec, state);

            buffer.WriteBigEndian<byte>(1);

            frame.Finish(ref buffer);
        }
    }
}
