using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates
{
    public interface ICertificate
    {
        CertificateType CertificateType { get; }
    }
}
