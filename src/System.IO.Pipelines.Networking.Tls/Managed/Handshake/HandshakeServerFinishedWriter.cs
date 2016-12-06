using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Handshake
{
    public class HandshakeServerFinishedWriter:IMessageWriter
    {
        public HandshakeServerFinishedWriter()
        {
        }

        public byte MessageType => (byte)HandshakeMessageType.Finished;

        public void WriteMessage(ref WritableBuffer buffer, ManagedConnectionContext context)
        {
            buffer.Write(new Span<byte>(context.ServerVerifyData));
        }
    }
}
