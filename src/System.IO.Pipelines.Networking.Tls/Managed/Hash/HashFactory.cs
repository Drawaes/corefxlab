using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Hash
{
    public class HashFactory
    {
        private readonly HashProvider[] _hashProviders;
        private readonly HashProvider[] _hmacProviders;
        private NativeBufferPool _pool;

        public HashFactory()
        {
            var arraySize = ((int[])Enum.GetValues(typeof(HashType))).Max() + 1;
            _hashProviders = new HashProvider[arraySize];
            _hmacProviders = new HashProvider[arraySize];
        }

        public HashProvider GetHashProvider(HashType algo)
        {
            int alg = (int)algo;
            if(alg < 0 || alg > _hashProviders.Length-1)
            {
                throw new ArgumentOutOfRangeException(nameof(algo));
            }
            var provider = _hashProviders[alg];
            if(provider != null)
            {
                return provider;
            }
            provider = new HashProvider(algo.ToString(),false);
            if(provider.IsValid)
            {
                _hashProviders[alg] = provider;
                return provider;
            }
            return null;
        }

        public HashProvider GetHmacProvider(HashType algo)
        {
            int alg = (int)algo;
            if (alg < 0 || alg > _hmacProviders.Length - 1)
            {
                throw new ArgumentOutOfRangeException(nameof(algo));
            }
            var provider = _hmacProviders[alg];
            if (provider != null)
            {
                return provider;
            }
            provider = new HashProvider(algo.ToString(), true);
            if (provider.IsValid)
            {
                _hmacProviders[alg] = provider;
                return provider;
            }
            return null;
        }

        public void Init()
        {
            int max = 0;
            for(int i = 0; i < _hmacProviders.Length;i++)
            {
                if(_hashProviders[i] != null && _hashProviders[i].BufferSizeNeededForState > max)
                {
                    max = _hashProviders[i].BufferSizeNeededForState;
                }
                if(_hmacProviders[i] != null && _hmacProviders[i].BufferSizeNeededForState > max)
                {
                    max = _hmacProviders[i].BufferSizeNeededForState;
                }
            }
            _pool = new NativeBufferPool(max, 100);
            for (int i = 0; i < _hmacProviders.Length; i++)
            {
                if (_hashProviders[i] != null)
                {
                    _hashProviders[i].SetBufferPool(_pool);
                }
                if (_hmacProviders[i] != null)
                {
                    _hmacProviders[i].SetBufferPool(_pool);
                }
            }
        }
    }
}
