using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.BulkCiphers
{
    internal interface IBulkCipherPal
    {
        IBulkCipherProvider GetCipher(BulkCipherType cipherType);
        IBulkCipherProvider GetCipher(string cipherType);
        void FinishSetup(int bufferPoolSize);
    }
}
