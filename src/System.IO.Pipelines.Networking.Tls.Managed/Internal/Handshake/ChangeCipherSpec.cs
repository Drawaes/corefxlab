using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Handshake
{
    internal class ChangeCipherSpec
    {
        public static void Write(ref WritableBuffer buffer, ConnectionState state)
        {
            var frame = new FrameWriter(ref buffer, TlsFrameType.ChangeCipherSpec, state);
            buffer.WriteBigEndian<byte>(1);
            frame.Finish(ref buffer);
        }
    }
}
