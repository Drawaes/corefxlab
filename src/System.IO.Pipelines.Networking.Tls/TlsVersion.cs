using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls
{
    public enum TlsVersion:ushort
    {
        Ssl3 = 0x0300,
        Tls10 = 0x0301,
        Tls11 = 0x0302,
        Tls12 = 0x0303,
    }
}
