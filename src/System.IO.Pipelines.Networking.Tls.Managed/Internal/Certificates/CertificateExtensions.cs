using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates
{
    internal static class CertificateExtensions
    {
        public static IHashInstance TryGetCertificateInstance(this ICertificatePal certPal, SignatureScheme cert)
        {
            if (((ushort)cert & 0x00FF) == 1)
            {
                var hashType = (HashType)((ushort)cert & 0xFF00);
                var certificate = certPal.TryGetCertificate(CertificateType.Rsa);
                return certificate?.GetHashandSignInstance(hashType, PaddingType.Pkcs1);
            }
            if ((ushort)cert >= 0x0804 && (ushort)cert <= 0x0806)
            {
                var hashType = (HashType)((ushort)cert & 0x00FF);
                var certificate = certPal.TryGetCertificate(CertificateType.Rsa);
                return certificate?.GetHashandSignInstance(hashType, PaddingType.Pss);
            }
            return null;
        }
    }
}
