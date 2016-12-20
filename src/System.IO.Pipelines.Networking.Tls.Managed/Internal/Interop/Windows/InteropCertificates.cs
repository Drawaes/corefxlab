using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Windows
{
    internal unsafe static class InteropCertificates
    {
        private const string Dll = "Ncrypt.dll";
        private const string MS_KEY_STORAGE_PROVIDER = "Microsoft Software Key Storage Provider";
        private const uint CERT_NCRYPT_KEY_SPEC = 0xFFFFFFFF;
        private const uint CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG = 0x00040000;
        private const string NCRYPT_KEY_USAGE_PROPERTY = "Key Usage";
        private const string AlgoProperty = "Algorithm Name";

        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private extern static NTResult NCryptOpenStorageProvider(out IntPtr phProvider, string pszProviderName, int dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private extern static NTResult NCryptGetProperty(IntPtr privateKey, string pszProperty, byte* result, uint cbOutput, out uint pcbResult, uint dwFlags);
        [DllImport("Crypt32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private extern static bool CryptAcquireCertificatePrivateKey(IntPtr pCert, uint dwFlags, out void* pvParameters, out IntPtr phCryptProvOrNCryptKey, out uint pdwKeySpec, out bool pfCallerFreeProvOrNCryptKey);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern NTResult NCryptSignHash(IntPtr hKey, void* pPaddingInfo, IntPtr pbHashValue, int cbHashValue, IntPtr pbSignature, int cbSignature, out int pcbResult, Padding dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern NTResult NCryptDecrypt(IntPtr hKey, IntPtr pbInput, int cbInput, IntPtr pPaddingInfo, IntPtr pbOutput, int cbOutput, out int pcbResult, uint dwFlags);

        internal static readonly IntPtr s_storageProvider;

        [StructLayout(LayoutKind.Sequential)]
        internal struct BCRYPT_PKCS1_PADDING_INFO
        {
            internal IntPtr pszAlgId;
        }

        internal enum Padding : uint
        {
            NCRYPT_NO_PADDING_FLAG = 0x00000001,
            NCRYPT_PAD_PKCS1_FLAG = 0x00000002,
            NCRYPT_PAD_OAEP_FLAG = 0x00000004,
        }

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
            IntPtr storageProvider;
            ExceptionHelper.CheckReturnCode(NCryptOpenStorageProvider(out storageProvider, MS_KEY_STORAGE_PROVIDER, 0));
            s_storageProvider = storageProvider;
        }

        public static IntPtr GetPrivateKeyHandle(X509Certificate2 cert)
        {
            IntPtr keyPointer;
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

        public static KeyUse GetKeyUse(IntPtr keyPointer)
        {
            var key = KeyUse.NONE;
            uint resultSize;
            ExceptionHelper.CheckReturnCode(NCryptGetProperty(keyPointer,NCRYPT_KEY_USAGE_PROPERTY,(byte*) &key, 4, out resultSize, 0));
            return key;
        }

        public static string GetPrivateKeyAlgo(IntPtr keyPointer)
        {
            string algo;
            uint length;
            ExceptionHelper.CheckReturnCode(NCryptGetProperty(keyPointer, AlgoProperty, null, 0, out length, 0));
            byte* buffer = stackalloc byte[(int)length];
            ExceptionHelper.CheckReturnCode(NCryptGetProperty(keyPointer, AlgoProperty, buffer, length, out length, 0));
            algo = Marshal.PtrToStringUni((IntPtr)buffer);
            return algo;
        }

        public static int GetKeySize(IntPtr keyPointer)
        {
            int keyUse;
            uint result;
            ExceptionHelper.CheckReturnCode(NCryptGetProperty(keyPointer, "Length", (byte*)&keyUse, 4, out result, 0));
            return keyUse;
        }
    }
}
