using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Unix;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.BulkCiphers.Unix
{
    internal class UnixBulkCipherPal : IBulkCipherPal
    {
        private static readonly int s_NumberOfBulkCipherProvider = ((int[])Enum.GetValues(typeof(BulkCipherType))).Max() + 1;
        private readonly BulkCipherProvider[] _providers = new BulkCipherProvider[s_NumberOfBulkCipherProvider];

        public UnixBulkCipherPal()
        {
            _providers[(int)BulkCipherType.AES_128_GCM] = new BulkCipherProvider(InteropBulkCiphers.EVP_aes_128_gcm(),true);
            _providers[(int)BulkCipherType.AES_256_GCM] = new BulkCipherProvider(InteropBulkCiphers.EVP_aes_256_gcm(), true);
        }

        public IBulkCipherProvider GetCipher(BulkCipherType cipherType)
        {
            return _providers[(int)cipherType];
        }

        public void FinishSetup(int bufferPoolSize)
        {
        }
    }
}
