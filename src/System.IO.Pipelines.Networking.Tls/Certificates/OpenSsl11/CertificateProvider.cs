using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using static Interop.LibCrypto;

namespace System.IO.Pipelines.Networking.Tls.Certificates.OpenSsl11
{
    public class CertificateProvider
    {
        public unsafe ICertificate LoadCertificate(X509Certificate2 certificate)
        {
            var data = certificate.Export(X509ContentType.Pkcs12, "");
            IntPtr pk12Pointer = IntPtr.Zero;
            fixed (byte* ptr = data)
            {
                byte* ptr2 = ptr;
                pk12Pointer = d2i_PKCS12(ref pk12Pointer,ref ptr2, data.Length);
            }
            try
            {
                EVP_PKEY key;
                X509 x509;
                ThrowOnError(PKCS12_parse(pk12Pointer, "", out key, out x509, IntPtr.Zero));
                var name = OBJ_nid2ln(EVP_PKEY_base_id(key));
                switch(name)
                {
                    case "id-ecPublicKey":
                        return new EcdsaCertificate(key, x509);
                    case "rsaEncryption":
                         return new RsaCertificate(key, x509);
                    default:
                        throw new NotImplementedException();
                }
            }
            finally
            {
                PKCS12_free(pk12Pointer);
            }
        }
    }
}
