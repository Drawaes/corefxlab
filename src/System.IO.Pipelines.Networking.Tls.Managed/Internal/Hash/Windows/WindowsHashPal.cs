using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash.Windows
{
    internal class WindowsHashPal : IHashPal
    {
        private readonly HashProvider[] _hashProviders;
        private NativeBufferPool _pool;

        public WindowsHashPal()
        {
            var arraySize = ((byte[])Enum.GetValues(typeof(HashType))).Max() + 1;
            _hashProviders = new HashProvider[arraySize];
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
            provider = new HashProvider(algo);
            if (provider.IsValid)
            {
                _hashProviders[alg] = provider;
                return provider;
            }
            return null;
        }

        public void FinishSetup(int bufferPoolSize)
        {
            int max = 0;
            for (int i = 0; i < _hashProviders.Length; i++)
            {
                if (_hashProviders[i] != null && _hashProviders[i].BufferSizeNeededForState > max)
                {
                    max = _hashProviders[i].BufferSizeNeededForState;
                }
            }
            _pool = new NativeBufferPool(max, bufferPoolSize);
            for (int i = 0; i < _hashProviders.Length; i++)
            {
                if (_hashProviders[i] != null)
                {
                    _hashProviders[i].SetBufferPool(_pool);
                }
            }
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
    }
}
