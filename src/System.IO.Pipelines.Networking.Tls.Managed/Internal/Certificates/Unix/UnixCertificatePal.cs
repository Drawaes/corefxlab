using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Unix;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates.Unix
{
    internal class UnixCertificatePal:ICertificatePal
    {
        private ICertificate[] _certificates;

        private ICertificate GetCertificate(X509Certificate2 certificate)
        {
            var cert = certificate.Export(X509ContentType.Pkcs12,"");
            IntPtr privateKey;
            var certType =  InteropCertificates.LoadCertificate(cert, out privateKey);
            if(privateKey == IntPtr.Zero)
            {
                return null;
            }
            switch (certType)
            {
                case CertificateType.Rsa:
                    return new RsaCertificate(privateKey, certificate);
                default:
                    throw new NotImplementedException("Unsupported Certificate type");
            }
        }

        public ICertificate TryGetCertificate(CertificateType certType)
        {
            for (int i = 0; i < _certificates.Length; i++)
            {
                if (_certificates[i].CertificateType == certType)
                {
                    return _certificates[i];
                }
            }
            return null;
        }

        public void LoadCertificates(X509Certificate2[] certificates)
        {
            var certList = new List<ICertificate>();
            foreach (var cert in certificates)
            {
                var iCert = GetCertificate(cert);
                if (iCert != null)
                {
                    certList.Add(iCert);
                }
            }
            _certificates = certList.ToArray();
        }
    }
}
