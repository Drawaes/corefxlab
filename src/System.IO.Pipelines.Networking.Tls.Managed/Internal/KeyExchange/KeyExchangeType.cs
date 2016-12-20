using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.KeyExchange
{
    internal enum KeyExchangeType
    {
        None = 0,
        DH = 1,
        DHE = 2,
        ECDH = 3,
        ECDHE= 4,
    }
}
