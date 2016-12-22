using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Unix;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash.Unix
{
    internal class UnixHashPal : IHashPal
    {
        private static readonly int s_providersLength = ((byte[])Enum.GetValues(typeof(HashType))).Max() + 1;
        private readonly HashProvider[] _hashProviders = new HashProvider[s_providersLength];

        public UnixHashPal()
        {
            _hashProviders[(int)HashType.SHA256] = new HashProvider(InteropHash.EVP_sha256(), HashType.SHA256);
            _hashProviders[(int)HashType.SHA384] = new HashProvider(InteropHash.EVP_sha384(), HashType.SHA384);
        }

        public void Dispose()
        {
            for (int i = 0; i < _hashProviders.Length; i++)
            {
                try
                {
                    _hashProviders[i]?.Dispose();
                }
                catch { }
            }
        }

        public void FinishSetup(int poolSize)
        {
            //Nothing to do, openssl manages it's own memory
        }

        public IHashProvider GetHashProvider(string algo)
        {
            HashType hashType;
            if (Enum.TryParse(algo, true, out hashType))
            {
                return GetHashProvider(hashType);
            }
            return null;
        }

        public IHashProvider GetHashProvider(HashType algo)
        {
            var alg = (int)algo;
            if (alg < 0 || alg > _hashProviders.Length - 1)
            {
                throw new ArgumentOutOfRangeException(nameof(algo));
            }
            return _hashProviders[alg];
        }
    }
}
