using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Hashes;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Certificates
{
    public interface ICertificate : IDisposable
    {
        CertificateType CertificateType { get; }
        string Curve { get; }
        ISignatureInstance GetSignatureInstance(IHashInstance hash);
    }
}
