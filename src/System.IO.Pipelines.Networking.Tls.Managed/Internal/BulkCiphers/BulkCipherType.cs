using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.BulkCiphers
{
    internal enum BulkCipherType
    {
        TripleDES_EDE_CBC = 0,
        AES_128_CBC = 1,
        AES_128_GCM = 2,
        AES_256_CBC = 3,
        AES_256_GCM = 4,
    }
}
