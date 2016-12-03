using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.BulkCiphers
{
    public class BulkCipherFactory
    {
        private readonly BulkCipherProvider[] _providers;

        public BulkCipherFactory()
        {
            var max = ((int[])Enum.GetValues(typeof(BulkCipherType))).Max() + 1;
            _providers = new BulkCipherProvider[max];
        }

        public BulkCipherProvider GetCipher(BulkCipherType cipherType)
        {
            int alg = (int)cipherType;
            if (alg < 0 || alg > _providers.Length - 1)
            {
                throw new ArgumentOutOfRangeException(nameof(cipherType));
            }
            var provider = _providers[alg];
            if (provider != null)
            {
                return provider;
            }
            provider = new BulkCipherProvider(cipherType.ToString());
            if (provider.IsValid)
            {
                _providers[alg] = provider;
                return provider;
            }
            return null;
        }


    }
}
