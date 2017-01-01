using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using static Interop.LibCrypto;

namespace System.IO.Pipelines.Networking.Tls.Hashes.OpenSsl11
{
    public class HashProvider:IHashProvider
    {
        public IHashInstance GetHashInstance(HashType hashType)
        {
            IntPtr type;
            switch (hashType)
            {
                case HashType.SHA256:
                    type = EVP_sha256;
                    break;
                case HashType.SHA384:
                    type = EVP_sha384;
                    break;
                case HashType.SHA512:
                    type = EVP_sha512;
                    break;
                default:
                    throw new InvalidOperationException();
            }
            var ctx = EVP_MD_CTX_new();
            ThrowOnError(EVP_DigestInit_ex(ctx, type, IntPtr.Zero));
            int size = EVP_MD_size(type);
            return new HashInstance(ctx, size);
        }
    }
}
