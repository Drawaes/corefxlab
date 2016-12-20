using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash
{
    internal interface IHashPal : IDisposable
    {
        IHashProvider GetHashProvider(HashType algo);
        IHashProvider GetHashProvider(string algo);
        void FinishSetup(int poolSize);
    }
}
