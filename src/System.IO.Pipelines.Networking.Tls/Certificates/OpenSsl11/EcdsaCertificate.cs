using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Hashes;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using static Interop.LibCrypto;

namespace System.IO.Pipelines.Networking.Tls.Certificates.OpenSsl11
{
    public class EcdsaCertificate:ICertificate
    {
        private EVP_PKEY _key;
        private X509 _certificate;
        private string _curveName;
        internal EcdsaCertificate(EVP_PKEY privateKey, X509 certificate)
        {
            _key = privateKey;
            _certificate = certificate;
            var key = EVP_PKEY_get0_EC_KEY(_key);
            var group = EC_KEY_get0_group(key);
            var curveName = EC_GROUP_get_curve_name(group);

            _curveName = OBJ_nid2ln(curveName);
        }

        public CertificateType CertificateType => CertificateType.Ecdsa;

        public string Curve => _curveName;

        public void Dispose()
        {
            _key.Free();
            _certificate.Free();
            GC.SuppressFinalize(this);
        }

        public ISignatureInstance GetSignatureInstance(IHashInstance hash)
        {
            return new EcdsaSignatureInstance();
        }

        ~EcdsaCertificate()
        {
            Dispose();
        }
    }
}
