using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.TlsSpec
{
    public enum TlsVersions:ushort
    {
        Tls1 = 0x0301,
        None = 0,
        Tls12 = 0x0303,
        Tls13 = 0x0304
    }
}
