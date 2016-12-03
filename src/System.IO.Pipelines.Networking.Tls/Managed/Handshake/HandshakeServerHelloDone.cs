using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Handshake
{
    public class HandshakeServerHelloDone : IMessageWriter
    {
        public byte MessageType => (byte)HandshakeMessageType.ServerHelloDone;

        public void WriteMessage(ref WritableBuffer buffer, ManagedConnectionContext context)
        {
        }
    }
}
