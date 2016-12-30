using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates
{
    internal enum PaddingType
    {
        Pkcs1 = 0x00000002,    // NCryptEncrypt/Decrypt or NCryptSignHash/VerifySignature
        Oaep = 0x00000004,     // NCryptEncrypt/Decrypt
        Pss = 0x00000008,
    }
}
