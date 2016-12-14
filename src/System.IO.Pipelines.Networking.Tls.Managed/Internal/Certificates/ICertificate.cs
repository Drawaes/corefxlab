using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates
{
    internal unsafe interface ICertificate
    {
        CertificateType CertificateType { get; }
        byte[] RawData { get;}
        int SignatureSize { get;}

        void SignHash(IntPtr hashId, Memory<byte> outputBuffer, byte* hash, int hashLength);
    }
}
