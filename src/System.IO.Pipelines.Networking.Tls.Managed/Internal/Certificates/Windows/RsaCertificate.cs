﻿using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Windows;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using static System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Windows.InteropCertificates;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates.Windows
{
    internal class RsaCertificate:ICertificate
    {
        private IntPtr _privateKey;        
        private X509Certificate2 _certificate;
        private int _keyLength;

        public RsaCertificate(IntPtr privateKey, X509Certificate2 certificate)
        {
            _privateKey = privateKey;
            _certificate = certificate;
            _keyLength = GetKeySize(_privateKey) / 8;
        }

        public CertificateType CertificateType => CertificateType.Rsa;
        public byte[] RawData => _certificate.RawData;
        public int SignatureSize => _keyLength;

        public unsafe void SignHash(IHashProvider hashProvider, Memory<byte> outputBuffer, byte* hash, int hashLength)
        {
            var paddInfo = new BCRYPT_PKCS1_PADDING_INFO();
            paddInfo.pszAlgId = hashProvider.AlgId;
            void* outputPtr;
            if(!outputBuffer.TryGetPointer(out outputPtr))
            {
                throw new InvalidOperationException("Could not get pointer");
            }
            int result;
            ExceptionHelper.CheckReturnCode(
                NCryptSignHash(_privateKey, &paddInfo, (IntPtr)hash, hashLength, (IntPtr)outputPtr , outputBuffer.Length, out result, InteropCertificates.Padding.NCRYPT_PAD_PKCS1_FLAG));
        }
        
        public int Decrypt(IntPtr cipherText, int cipherTextLength, IntPtr plainText, int plainTextLength)
        {
            int returnResult;
            ExceptionHelper.CheckReturnCode(NCryptDecrypt(_privateKey, cipherText, cipherTextLength, IntPtr.Zero, plainText, plainTextLength, out returnResult, (uint)InteropCertificates.Padding.NCRYPT_PAD_PKCS1_FLAG));
            return returnResult;
        }
    }
}
