using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Hashes;
using System.Linq;
using System.Threading.Tasks;
using static Interop.LibCrypto;

namespace System.IO.Pipelines.Networking.Tls.Certificates.OpenSsl11
{
    public sealed class RsaCertificate : ICertificate
    {
        EVP_PKEY _key;
        X509 _certificate;

        internal RsaCertificate(EVP_PKEY privateKey, X509 certificate)
        {
            _key = privateKey;
        }

        public CertificateType CertificateType => CertificateType.Rsa;

        public string Curve => null;

        public void Dispose()
        {
            _key.Free();
            _certificate.Free();
            GC.SuppressFinalize(this);
        }

        public ISignatureInstance GetSignatureInstance(IHashInstance hash)
        {
            throw new NotImplementedException();
        }

        ~RsaCertificate()
        {
            Dispose();
        }
    }
}
