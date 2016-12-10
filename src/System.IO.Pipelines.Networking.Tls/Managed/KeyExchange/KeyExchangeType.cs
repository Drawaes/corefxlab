using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.KeyExchange
{
    public enum KeyExchangeType:byte
    {
        //Numbers from https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
        //enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) }
        //SignatureAlgorithm;
        RSA = 1,
        DH,
        DHE,
        ECDH,
        ECDHE,
        PSK,
        DHE_RSA,
        DH_DSS,
        DHE_PSK,
        DH_RSA,
        RSA_PSK,
        DHE_DSS,
        ECDH_ECDSA,
        ECDHE_ECDSA,
        ECDH_RSA,
        ECDHE_RSA,
        ECDHE_PSK
    }
}
