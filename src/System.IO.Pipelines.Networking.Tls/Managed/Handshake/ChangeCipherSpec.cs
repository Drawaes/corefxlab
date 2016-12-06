using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Handshake
{
    public class ChangeCipherSpec : IMessageWriter 
    {
        public byte MessageType => (byte)TlsFrameType.ChangeCipherSpec;

        public void WriteMessage(ref WritableBuffer buffer, ManagedConnectionContext context)
        {
            buffer.WriteBigEndian<byte>(1);
        }
    }
}