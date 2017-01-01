using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Hashes
{
    public interface IHashInstance : IDisposable
    {
        int HashLength { get; }
        void HashData(Memory<byte> dataToHash);
        void HashData(ReadableBuffer datatToHash);
        int InterimHash(Memory<byte> outputBuffer);
        int FinishHash(Memory<byte> outputBuffer);
    }
}
