using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Certificates
{
    public interface ISignatureInstance
    {
        int SignData(Memory<byte> buffer, Memory<byte> outputBuffer);
    }
}
