using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Unix;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using static System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Unix.InteropCertificates;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates.Unix
{
    internal class RsaCertificate : ICertificate
    {
        private IntPtr _privateKey;
        private X509Certificate2 _certificate;
        private int _keyLength;
        private CipherList _cipherList;
        
        public RsaCertificate(IntPtr privateKey, X509Certificate2 certificate, CipherList cipherList)
        {
            _cipherList = cipherList;
            _privateKey = privateKey;
            _certificate = certificate;
            _keyLength = RSAKeySize(_privateKey);
        }

        public int SignatureSize => _keyLength;

        public byte[] RawData => _certificate.RawData;

        public CertificateType CertificateType => CertificateType.Rsa;

        public unsafe void SignHash(IHashProvider hashId, byte* outputBuffer,int outputBufferLength,  byte* hash, int hashLength, PaddingType padding)
        {
            var ctx = ExceptionHelper.CheckPointerError(EVP_PKEY_CTX_new(_privateKey, IntPtr.Zero));
            try
            {
                ExceptionHelper.CheckOpenSslError(EVP_PKEY_sign_init(ctx));
                SetRSAPadding(ctx);
                SetRSADigest(ctx,  hashId.AlgId);
                ExceptionHelper.CheckOpenSslError(EVP_PKEY_sign(ctx, (IntPtr)outputBuffer, ref outputBufferLength ,(IntPtr)hash, hashLength));
            }
            finally
            {
                EVP_PKEY_CTX_free(ctx);
            }
        }

        public int Decrypt(IntPtr cipherText, int cipherTextLength, IntPtr plainText, int plainTextLength)
        {
            var ctx = ExceptionHelper.CheckPointerError(EVP_PKEY_CTX_new(_privateKey, IntPtr.Zero));
            try
            {
                ExceptionHelper.CheckOpenSslError(EVP_PKEY_decrypt_init(ctx));
                SetRSAPadding(ctx);
                ExceptionHelper.CheckOpenSslError(EVP_PKEY_decrypt(ctx, plainText, ref plainTextLength, cipherText, cipherTextLength));
                return plainTextLength;
            }
            finally
            {
                EVP_PKEY_CTX_free(ctx);
            }
        }

        public IHashAndSignInstance GetHashandSignInstance(HashType hashType, PaddingType padding)
        {
            var hash = _cipherList.HashFactory.GetHashProvider(hashType);
            if(hash == null)
            {
                return null;
            }
            return new HashAndSignRsaInstance(hash, padding, this);
        }
    }
}
