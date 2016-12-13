using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates
{
    public class RsaCertificate:ICertificate
    {
        private IntPtr _privateKey;        
        private X509Certificate2 _certificate;

        public RsaCertificate(IntPtr privateKey, X509Certificate2 certificate)
        {
            _privateKey = privateKey;
            _certificate = certificate;
        }

        public CertificateType CertificateType => CertificateType.Rsa;

    }
}
