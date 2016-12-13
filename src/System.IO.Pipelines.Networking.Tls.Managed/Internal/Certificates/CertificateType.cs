using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates
{
    public enum CertificateType:byte
    {
        //Numbers from https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
        //enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) }
        //SignatureAlgorithm;
        Anonymous = 0,
        Rsa = 1,
        Dsa = 2,
        Ecdsa = 3
    }
}
