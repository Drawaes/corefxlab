using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal
{
    internal partial class TlsImplementation
    {
        public static unsafe void P_Hash12(HashProvider hash, byte[] keyMaterial, byte[] secret, byte[] seed)
        {
            fixed (byte* secretPtr = secret)
            {
                var a1 = stackalloc byte[hash.HashLength + seed.Length];
                Span<byte> a1Span = new Span<byte>(a1, hash.HashLength + seed.Length);
                Span<byte> seedSpan = new Span<byte>(seed);
                seedSpan.CopyTo(a1Span.Slice(hash.HashLength));
                var seedPtr = a1 + hash.HashLength;
                hash.HashValue(a1, hash.HashLength, secretPtr, secret.Length, seedPtr, seed.Length);
                var currentKeyData = stackalloc byte[hash.HashLength];

                int keyMaterialIndex = 0;
                while (true)
                {
                    hash.HashValue(currentKeyData, hash.HashLength, secretPtr, secret.Length, a1, hash.HashLength + seed.Length);
                    for (int i = 0; i < hash.HashLength; i++)
                    {
                        keyMaterial[keyMaterialIndex] = currentKeyData[i];
                        keyMaterialIndex++;
                        if (keyMaterialIndex == keyMaterial.Length)
                        {
                            return;
                        }
                    }
                    hash.HashValue(a1, hash.HashLength, secretPtr, secret.Length, a1, hash.HashLength);
                }
            }
        }
    }
}
