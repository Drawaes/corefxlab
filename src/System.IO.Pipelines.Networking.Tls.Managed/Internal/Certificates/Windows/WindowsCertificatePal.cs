using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Windows;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates.Windows
{
    internal class WindowsCertificatePal:ICertificatePal
    {
        private ICertificate[] _certificates; 

        private ICertificate GetCertificate(X509Certificate2 certificate)
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

        public void LoadCertificates(X509Certificate2[] certificates)
        {
            var certList = new List<ICertificate>();
            foreach(var cert in certificates)
            {
                var iCert = GetCertificate(cert);
                if(iCert != null)
                {
                    certList.Add(iCert);
                }
            }
            _certificates = certList.ToArray();
        }

        public ICertificate TryGetCertificate(CertificateType certType)
        {
            for(int i = 0; i < _certificates.Length;i++)
            {
                if(_certificates[i].CertificateType == certType)
                {
                    return _certificates[i];
                }
            }
            return null;
        }
    }
}
