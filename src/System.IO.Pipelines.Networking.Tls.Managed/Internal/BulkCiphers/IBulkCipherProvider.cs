using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.BulkCiphers
{
    internal interface IBulkCipherProvider:IDisposable
    {
        bool IsValid { get;}
        int NonceSaltLength { get;}
        int KeySizeInBytes { get;}
        bool RequiresHmac { get;}
        unsafe IBulkCipherInstance GetCipherKey(byte* key, int keyLength,CipherSuite suite);
    }
}
