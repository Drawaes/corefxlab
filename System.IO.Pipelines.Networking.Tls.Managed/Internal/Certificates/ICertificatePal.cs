using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates
{
    public interface ICertificatePal
    {
        ICertificate GetCertificate(X509Certificate2 certificate);
    }
}
