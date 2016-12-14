using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.KeyExchange
{
    internal enum KeyExchangeType
    {
        None,
        DH,
        DHE,
        ECDH,
        ECDHE,
    }
}
