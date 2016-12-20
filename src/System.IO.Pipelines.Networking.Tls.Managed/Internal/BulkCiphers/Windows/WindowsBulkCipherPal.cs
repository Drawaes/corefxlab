using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.BulkCiphers.Windows
{
    internal class WindowsBulkCipherPal : IBulkCipherPal
    {
        private static readonly int s_NumberOfBulkCipherProvider = ((int[])Enum.GetValues(typeof(BulkCipherType))).Max() + 1;
        private readonly BulkCipherProvider[] _providers = new BulkCipherProvider[s_NumberOfBulkCipherProvider];
        private NativeBufferPool _pool;

        public IBulkCipherProvider GetCipher(string cipherType)
        {
            BulkCipherType cipher;
            if(!Enum.TryParse(cipherType, out cipher))
            {
                return null;
            }
            return GetCipher(cipher);
        }

        public IBulkCipherProvider GetCipher(BulkCipherType cipherType)
        {
            var provider = _providers[(int)cipherType];
            if(provider == null)
            {
                provider = new BulkCipherProvider(cipherType.ToString());
                _providers[(int)cipherType] = provider;
            }
            
            if (provider.IsValid)
            {
                return provider;
            }
            return null;
        }

        public void FinishSetup(int bufferPoolSize)
        {
            int max = 0;
            for (int i = 0; i < _providers.Length; i++)
            {
                if (_providers[i] != null && _providers[i].BufferSizeNeededForState > max)
                {
                    max = _providers[i].BufferSizeNeededForState;
                }
            }
            _pool = new NativeBufferPool(max, bufferPoolSize * 2);
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
