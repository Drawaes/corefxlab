using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.BulkCiphers
{
    public class BulkCipherFactory
    {
        private readonly BulkCipherProvider[] _providers;
        private NativeBufferPool _pool;

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

        public void Init()
        {
            int max = 0;
            for (int i = 0; i < _providers.Length; i++)
            {
                if (_providers[i] != null && _providers[i].BufferSizeNeededForState > max)
                {
                    max = _providers[i].BufferSizeNeededForState;
                }
            }
            _pool = new NativeBufferPool(max, 100);
            for (int i = 0; i < _providers.Length; i++)
            {
                if (_providers[i] != null)
                {
                    _providers[i].SetBufferPool(_pool);
                }
            }
        }
    }
}
