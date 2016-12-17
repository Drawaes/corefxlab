using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates
{
    internal unsafe interface ICertificate
    {
        CertificateType CertificateType { get; }
        byte[] RawData { get;}
        int SignatureSize { get;}

        void SignHash(HashProvider hashId, Memory<byte> outputBuffer, byte* hash, int hashLength);
        int Decrypt(IntPtr cipherText, int cipherTextLength, IntPtr plainText, int plainTextLength);
    }
}
