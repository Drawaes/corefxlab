using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates
{
    internal enum SignatureScheme:ushort
    {
        rsa_pskcs1_sha1 = 0x0201,
        rsa_pskcs1_sha256 = 0x0401,
        rsa_pskcs1_sha384 = 0x0501,
        rsa_pskcs1_sha512 = 0x0601,
        ecdsa_secp256r1_sha256 = 0x0403,
        ecdsa_secp384r1_sha384 = 0x0503,
        ecdsa_secp521r1_sha512 = 0x0603,

        rsa_pss_sha256 = 0x0804,
        rsa_pss_sha384 = 0x0805,
        rsa_pss_sha512 = 0x0806,

        ed25519 = 0x0807,
        ed448 = 0x0808
    }
}
