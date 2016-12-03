using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Handshake
{
    public class HandshakeServerCertificateWriter : IMessageWriter
    {
        public byte MessageType => (byte)HandshakeMessageType.Certificate;

        public void WriteMessage(ref WritableBuffer buffer, ManagedConnectionContext context)
        {
            HandshakeMessageWriter<HandshakeServerCertificateWriter>.Write24BitNumber(context.SecurityContext.Certificate.RawData.Length + 3, ref buffer);
            HandshakeMessageWriter<HandshakeServerCertificateWriter>.Write24BitNumber(context.SecurityContext.Certificate.RawData.Length, ref buffer);
            buffer.Ensure(context.SecurityContext.Certificate.RawData.Length);
            buffer.Write(new ReadOnlySpan<byte>(context.SecurityContext.Certificate.RawData));
        }
    }
}
