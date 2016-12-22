using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
using static global::Interop.NCrypt;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Windows
{
    internal unsafe static class InteropCertificates
    {
        private const string MS_KEY_STORAGE_PROVIDER = "Microsoft Software Key Storage Provider";
        private const uint CERT_NCRYPT_KEY_SPEC = 0xFFFFFFFF;
        private const uint CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG = 0x00040000;
        private const string NCRYPT_KEY_USAGE_PROPERTY = "Key Usage";
        private const string AlgoProperty = "Algorithm Name";
                
        [DllImport("Crypt32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private extern static bool CryptAcquireCertificatePrivateKey(IntPtr pCert, uint dwFlags, out void* pvParameters, out SafeNCryptKeyHandle phCryptProvOrNCryptKey, out uint pdwKeySpec, out bool pfCallerFreeProvOrNCryptKey);

        internal static readonly SafeNCryptProviderHandle s_storageProvider;
                
        [Flags]
        internal enum KeyUse : uint
        {
            NONE = 0,
            NCRYPT_ALLOW_DECRYPT_FLAG = 0x00000001,//	The key can be used for decryption.
            NCRYPT_ALLOW_SIGNING_FLAG = 0x00000002,//	The key can be used for signing.
            NCRYPT_ALLOW_KEY_AGREEMENT_FLAG = 0x00000004,//	The key can be used for secret agreement encryption.
            NCRYPT_ALLOW_ALL_USAGES = 0x00ffffff,//	The key can be used for any purpose.
        }

        static InteropCertificates()
        {
            SafeNCryptProviderHandle storageProvider;
            ExceptionHelper.CheckReturnCode(NCryptOpenStorageProvider(out storageProvider, MS_KEY_STORAGE_PROVIDER, 0));
            s_storageProvider = storageProvider;
        }

        internal static SafeNCryptKeyHandle GetPrivateKeyHandle(X509Certificate2 cert)
        {
            SafeNCryptKeyHandle keyPointer;
            void* stuff;
            uint keySpec;
            bool needToFree;
            var result = CryptAcquireCertificatePrivateKey(cert.Handle, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, out stuff, out keyPointer, out keySpec, out needToFree);
            if (!result || keySpec != CERT_NCRYPT_KEY_SPEC)
            {
                throw new InvalidOperationException();
            }
            return keyPointer;
        }

        internal static KeyUse GetKeyUse(SafeNCryptKeyHandle keyPointer)
        {
            var key = KeyUse.NONE;
            int resultSize;
            ExceptionHelper.CheckReturnCode(NCryptGetProperty(keyPointer,NCRYPT_KEY_USAGE_PROPERTY,(byte*) &key, 4, out resultSize, 0));
            return key;
        }

        internal static string GetPrivateKeyAlgo(SafeNCryptKeyHandle keyPointer)
        {
            string algo;
            int length;
            ExceptionHelper.CheckReturnCode(NCryptGetProperty(keyPointer, AlgoProperty, null, 0, out length, 0));
            byte* buffer = stackalloc byte[length];
            ExceptionHelper.CheckReturnCode(NCryptGetProperty(keyPointer, AlgoProperty, buffer, length, out length, 0));
            algo = Marshal.PtrToStringUni((IntPtr)buffer);
            return algo;
        }

        internal static int GetKeySize(SafeNCryptKeyHandle keyPointer)
        {
            int keyUse;
            int result;
            ExceptionHelper.CheckReturnCode(NCryptGetProperty(keyPointer, "Length", (byte*)&keyUse, 4, out result, 0));
            return keyUse;
        }
    }
}
