using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Hashes;
using System.IO.Pipelines.Networking.Tls.TlsSpec;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Certificates
{
    public class CertificateList
    {
        private string[] _certificateHosts;
        private ICertificate[] _certificates;
        private OpenSsl11.CertificateProvider _provider = new OpenSsl11.CertificateProvider();

        public CertificateList(params X509Certificate2[] defaultCertificates)
        {
            _certificateHosts = new string[defaultCertificates.Length];
            _certificates = new ICertificate[defaultCertificates.Length];
            for(int i = 0; i < _certificates.Length;i++)
            {
                _certificates[i] = _provider.LoadCertificate(defaultCertificates[i]);
            }
        }

        public void AddHostCert(string serverName, X509Certificate2 certificate)
        {
            throw new NotImplementedException();
        }

        public ISignatureInstance GetSignatureInstance(SignatureScheme scheme, IHashProvider hashProvider)
        {
            if (((ushort)scheme & 0x00FF) == 0x03)
            {
                //See if we have a cert for ECDSA
                var cert = GetCertificate(null, CertificateType.Ecdsa);
                if(cert == null)
                {
                    return null;
                }
                if(!scheme.ToString().Contains(cert.Curve))
                {
                    return null;
                }
                HashType hash;
                if(!Enum.TryParse(scheme.ToString().Split('_').Last(),true, out hash))
                {
                    return null;
                }
                return cert.GetSignatureInstance(hashProvider.GetHashInstance(hash));
            }

            return null;
        }

        public ICertificate GetCertificate(string host, CertificateType type)
        {
            for(int i = 0; i < _certificates.Length; i++)
            {
                if(_certificateHosts[i] != host)
                {
                    continue;
                }
                var cert = _certificates[i];
                if(cert.CertificateType != type)
                {
                    continue;
                }
                return _certificates[i];
            }
            return null;
        }
    }
}
