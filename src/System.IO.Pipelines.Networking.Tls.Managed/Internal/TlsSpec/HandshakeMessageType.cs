using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.TlsSpec
{
    public enum HandshakeMessageType : byte
    {
        HelloRequest = 0,
        ClientHello = 1,
        ServerHello = 2,
        Hello_Retry_Request = 6,
        NewSessionTicket = 4,
        Certificate = 11,
        ServerKeyExchange = 12,
        CertificateRequest = 13,
        ServerHelloDone = 14,
        CertificateVerify = 15,
        ClientKeyExchange = 16,
        Finished = 20,
        //Own value for errors
        Incomplete = 254,
        Invalid = 255,
    }
}
