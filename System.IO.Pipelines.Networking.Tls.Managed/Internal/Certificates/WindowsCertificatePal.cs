using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates
{
    internal class WindowsCertificatePal
    {
        public ICertificate GetCertificate(X509Certificate2 certificate)
        {
            var privateKey = InteropCertificates.GetPrivateKeyHandle(certificate);
            var certType = (CertificateType)Enum.Parse(typeof(CertificateType), InteropCertificates.GetPrivateKeyAlgo(privateKey), true);
            switch (certType)
            {
                case CertificateType.Rsa:
                    return new RsaCertificate(privateKey, certificate);
                default:
                    throw new NotImplementedException("Unsupported Certificate type");
            }
        }
    }
}
