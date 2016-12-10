using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Handshake
{
    public class HandshakeServerFinishedWriter:IMessageWriter
    {
        public byte MessageType => (byte)HandshakeMessageType.Finished;

        public void WriteMessage(ref WritableBuffer buffer, ManagedConnectionContext context)
        {
            var hashResult = context.ServerFinishedHash.Finish();
            var verifyData = new byte[12];
            ClientKeyExchange.P_hash(context.CipherSuite.Hmac, verifyData, context.MasterSecret, Enumerable.Concat(ManagedConnectionContext.s_serverfinishedLabel, hashResult).ToArray());
            buffer.Write(new Span<byte>(verifyData));
        }
    }
}
