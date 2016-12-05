using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.KeyExchange
{
    public enum KeyExchangeCipher
    {
        RSA,
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
