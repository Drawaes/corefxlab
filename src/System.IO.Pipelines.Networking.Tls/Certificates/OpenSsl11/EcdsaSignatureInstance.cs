using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Certificates.OpenSsl11
{
    public class EcdsaSignatureInstance : ISignatureInstance
    {
        public int SignData(Memory<byte> buffer, Memory<byte> outputBuffer)
        {
            throw new NotImplementedException();
        }
    }
}
