using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash
{
    public enum HashType : byte
    {
        SHA = 2,
        SHA256 = 4,
        SHA384 = 5
        //Numbers from https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
        //    md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
        //sha512(6)
    }
}
