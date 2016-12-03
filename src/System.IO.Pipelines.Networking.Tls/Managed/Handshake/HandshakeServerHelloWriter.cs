using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Internal.ManagedTls;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Handshake
{
    public class HandshakeServerHelloWriter : IMessageWriter
    {
        public byte MessageType => (byte)HandshakeMessageType.ServerHello;

        public unsafe void WriteMessage(ref WritableBuffer buffer, ManagedConnectionContext context)
        {
            //Need to write the version + 32 bytes of random == 35 bytes
            buffer.Ensure(35);
            buffer.WriteBigEndian<ushort>(0x0303);
            var memoryToFill = buffer.Memory.Slice(0,32);
            InteropRandom.GetRandom(memoryToFill);
            context.SetServerRandom(memoryToFill);
            buffer.Advance(32);

            //Write 0 for no session id at the moment
            buffer.Ensure(1);
            buffer.WriteBigEndian<byte>(0);

            //Write the ciphersuite, and compression method
            buffer.Ensure(3);
            buffer.WriteBigEndian(context.CipherSuite.CipherId);
            buffer.WriteBigEndian<byte>(0);
        }
    }
}
