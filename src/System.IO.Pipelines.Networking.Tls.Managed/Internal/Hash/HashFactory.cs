using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash
{
    public class HashFactory:IDisposable
    {
        private readonly HashProvider[] _hashProviders;
        private readonly HashProvider[] _hmacProviders;
        private NativeBufferPool _pool;
        
        public HashFactory()
        {
            var arraySize = ((byte[])Enum.GetValues(typeof(HashType))).Max() + 1;
            _hashProviders = new HashProvider[arraySize];
            _hmacProviders = new HashProvider[arraySize];
        }

        public void Dispose()
        {
            for(int i = 0; i < _hashProviders.Length; i++)
            {
                try
                {
                    _hashProviders[i]?.Dispose();
                }
                catch { }
                try
                {
                    _hmacProviders[i]?.Dispose();
                }
                catch { }
            }
        }

        public HashProvider GetHashProvider(HashType algo)
        {
            int alg = (int)algo;
            if (alg < 0 || alg > _hashProviders.Length - 1)
            {
                throw new ArgumentOutOfRangeException(nameof(algo));
            }
            var provider = _hashProviders[alg];
            if (provider != null)
            {
                return provider;
            }
            provider = new HashProvider(algo, false);
            if (provider.IsValid)
            {
                _hashProviders[alg] = provider;
                return provider;
            }
            return null;
        }

        public HashProvider GetHashProvider(string algo)
        {
            HashType hashType;
            if(Enum.TryParse(algo,true,out hashType))
            {
                return GetHashProvider(hashType);
            }
            return null;
        }

        public HashProvider GetHmacProvider(string algo)
        {
            HashType hashType;
            if (Enum.TryParse(algo, true, out hashType))
            {
                return GetHmacProvider(hashType);
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
            provider = new HashProvider(algo, true);
            if (provider.IsValid)
            {
                _hmacProviders[alg] = provider;
                return provider;
            }
            return null;
        }

        public void Init(int bufferPoolSize)
        {
            int max = 0;
            for (int i = 0; i < _hmacProviders.Length; i++)
            {
                if (_hashProviders[i] != null && _hashProviders[i].BufferSizeNeededForState > max)
                {
                    max = _hashProviders[i].BufferSizeNeededForState;
                }
                if (_hmacProviders[i] != null && _hmacProviders[i].BufferSizeNeededForState > max)
                {
                    max = _hmacProviders[i].BufferSizeNeededForState;
                }
            }
            _pool = new NativeBufferPool(max, bufferPoolSize);
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
