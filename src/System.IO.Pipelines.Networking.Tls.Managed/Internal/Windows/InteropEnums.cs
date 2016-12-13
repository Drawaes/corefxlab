using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Windows
{
    internal static class InteropEnums
    {
        [Flags]
        internal enum EnumAlgorithmsOptions : uint
        {
            BCRYPT_CIPHER_OPERATION = 0x00000001, // Include the cipher algorithms in the enumeration.
            BCRYPT_HASH_OPERATION = 0x00000002, // Include the hash algorithms in the enumeration.
            BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION = 0x00000004, //Include the asymmetric encryption algorithms in the enumeration.
            BCRYPT_SECRET_AGREEMENT_OPERATION = 0x00000008, // Include the secret agreement algorithms in the enumeration.
            BCRYPT_SIGNATURE_OPERATION = 0x00000010, // Include the signature algorithms in the enumeration.
            BCRYPT_RNG_OPERATION = 0x00000020, // Include the random number generator (RNG) algorithms in the enumeration.
        }
    }
}
