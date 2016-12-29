using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Windows;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
using static System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Windows.InteropCertificates;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates.Windows
{
    internal class RsaCertificate:ICertificate
    {
        private SafeNCryptKeyHandle _privateKey;        
        private X509Certificate2 _certificate;
        private int _keyLength;
        private CipherList _cipherList;

        public RsaCertificate(SafeNCryptKeyHandle privateKey, X509Certificate2 certificate, CipherList cipherList)
        {
            _privateKey = privateKey;
            _certificate = certificate;
            _keyLength = GetKeySize(_privateKey) / 8;
            _cipherList = cipherList;
        }

        public CertificateType CertificateType => CertificateType.Rsa;
        public byte[] RawData => _certificate.RawData;
        public int SignatureSize => _keyLength;

        public unsafe void SignHash(IHashProvider hashProvider, byte* outputBuffer,int outputBufferLength, byte* hash, int hashLength, PaddingType padding)
        {
            var paddInfo = new global::Interop.BCrypt.BCRYPT_PKCS1_PADDING_INFO();
            paddInfo.pszAlgId = hashProvider.AlgId;
            int result;
            ExceptionHelper.CheckReturnCode(global::Interop.NCrypt.NCryptSignHash(_privateKey, &paddInfo, hash, hashLength, outputBuffer , outputBufferLength, out result, (global::Interop.NCrypt.AsymmetricPaddingMode)padding));
        }
        
        public unsafe int Decrypt(IntPtr cipherText, int cipherTextLength, IntPtr plainText, int plainTextLength)
        {
            int returnResult;
            ExceptionHelper.CheckReturnCode(global::Interop.NCrypt.NCryptDecrypt(_privateKey, (byte*) cipherText, cipherTextLength, null,(byte*) plainText, plainTextLength, out returnResult, global::Interop.NCrypt.AsymmetricPaddingMode.NCRYPT_PAD_PKCS1_FLAG));
            return returnResult;
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
