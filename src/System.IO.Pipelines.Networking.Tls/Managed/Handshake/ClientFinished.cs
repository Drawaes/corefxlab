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
            var hashResult = context.ClientFinishedHash.Finish();
            ClientKeyExchange.P_hash(context.CipherSuite.Hmac, verifyData, context.MasterSecret, Enumerable.Concat(ManagedConnectionContext.s_clientfinishedLabel, hashResult).ToArray());
            context.ServerFinishedHash.HashData(buffer);
            //check all client data in constant time
            int currentIndex = 0;
            bool match = true;
            while(buffer.Length > 0)
            {
                if(currentIndex >= verifyData.Length)
                {
                    match = false;
                }
                else
                {
                    if(buffer.ReadLittleEndian<byte>() != verifyData[currentIndex])
                    {
                        match = false;
                    }
                }
                currentIndex ++;
                buffer = buffer.Slice(1);
            }
            if(!match)
            {
                throw new InvalidOperationException("Client Verify didn't match");
            }
            context.ReadyToSend = true;
        }
    }
}
