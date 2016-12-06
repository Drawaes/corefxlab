using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Handshake
{
    public static class ClientFinished
    {
        public static void ProcessClientFinished(ReadableBuffer buffer, ManagedConnectionContext context)
        {
            var verifyData = new byte[12];
            context.HandshakeHash.HashData(buffer);
            context.ReadyToSend = true;
        }
    }
}
