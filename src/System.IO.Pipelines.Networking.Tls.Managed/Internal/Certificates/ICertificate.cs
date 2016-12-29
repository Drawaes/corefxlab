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
        byte[] RawData { get; }
        int SignatureSize { get; }
        int Decrypt(IntPtr cipherText, int cipherTextLength, IntPtr plainText, int plainTextLength);
        void SignHash(IHashProvider hashProvider, byte* outputBuffer, int outputBufferLength, byte* hash, int hashLength, PaddingType padding);
        IHashAndSignInstance GetHashandSignInstance(HashType hashType, PaddingType padding);
    }
}
