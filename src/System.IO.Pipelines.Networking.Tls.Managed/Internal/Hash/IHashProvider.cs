using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash
{
    internal unsafe interface IHashProvider
    {
        int HashLength { get; }
        IntPtr AlgId { get; }
        bool IsValid { get; }
        int BufferSizeNeededForState { get; }
        HashType HashType { get; }
        int AlgIdLength { get; }
        IHashInstance GetLongRunningHash(byte[] hmacKey);
        void HmacValue(byte* output, int outputLength, byte* secret, int secretLength, byte* message, int messageLength);
    }
}
