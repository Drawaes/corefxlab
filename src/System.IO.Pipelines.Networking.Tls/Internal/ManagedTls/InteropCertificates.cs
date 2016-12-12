using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Internal.ManagedTls
{
    public unsafe static class InteropCertificates
    {
        private const string Dll = "Ncrypt.dll";

        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        public extern static ReturnCodes NCryptOpenStorageProvider(out IntPtr phProvider, [MarshalAs(UnmanagedType.LPWStr)] string pszProviderName, int dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        public extern static ReturnCodes NCryptFreeObject(IntPtr hObject);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        public extern static ReturnCodes NCryptOpenKey(IntPtr hProvider, out IntPtr keyPtr, [MarshalAs(UnmanagedType.LPWStr)] string pszKeyName, int dwLegacyKeySpec, int dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        public extern static ReturnCodes NCryptEnumKeys(IntPtr hProvider, void* unusedScope, out IntPtr result, ref IntPtr enumState, uint dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        public extern static ReturnCodes NCryptEnumStorageProviders(out uint pdwProviderCount, out IntPtr pProviderList, uint dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        public extern static ReturnCodes NCryptGetProperty(IntPtr privateKey, [MarshalAs(UnmanagedType.LPWStr)] string pszProperty, byte* result, uint cbOutput, out uint pcbResult, uint dwFlags);

        [DllImport("Crypt32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        public extern static bool CryptAcquireCertificatePrivateKey(IntPtr pCert, uint dwFlags, out void* pvParameters, out IntPtr phCryptProvOrNCryptKey,
        out uint pdwKeySpec, out bool pfCallerFreeProvOrNCryptKey);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        public extern static ReturnCodes NCryptDecrypt(IntPtr hKey, void* pbInput, int cbInput, void* pPaddingInfo, void* pbOutput, int cbOutput, out int pcbResult, uint dwFlags);

        public const string MS_KEY_STORAGE_PROVIDER = "Microsoft Software Key Storage Provider";
        public const string MS_SMART_CARD_KEY_STORAGE_PROVIDER = "Microsoft Smart Card Key Storage Provider";
        public const string MS_PLATFORM_KEY_STORAGE_PROVIDER = "Microsoft Platform Crypto Provider";
        private const string NCRYPT_KEY_USAGE_PROPERTY = "Key Usage";
        private const string BCRYPT_KEY_LENGTH = "KeyLength";
        public const uint CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG = 0x00040000;
        private const uint CERT_NCRYPT_KEY_SPEC = 0xFFFFFFFF;
        private const string AlgoProperty = "Algorithm Name";

        internal static readonly IntPtr s_storageProvider;

        static InteropCertificates()
        {
            IntPtr storageProvider;
            Interop.CheckReturnOrThrow(NCryptOpenStorageProvider(out storageProvider, MS_KEY_STORAGE_PROVIDER, 0));
            s_storageProvider = storageProvider;
        }

        public enum Padding : uint
        {
            NCRYPT_NO_PADDING_FLAG = 0x00000001,
            NCRYPT_PAD_PKCS1_FLAG = 0x00000002,
            NCRYPT_PAD_OAEP_FLAG = 0x00000004,
        }

        public static Memory<byte> DecryptInPlace(IntPtr ptr, Memory<byte> encryptedData)
        {
            void* bufferPointer;
            encryptedData.TryGetPointer(out bufferPointer);
            int totalWritten;
            var rc = NCryptDecrypt(ptr, bufferPointer, encryptedData.Length, null, bufferPointer, encryptedData.Length, out totalWritten, (uint)Padding.NCRYPT_PAD_PKCS1_FLAG);
            Interop.CheckReturnOrThrow(rc);
            return encryptedData.Slice(0, totalWritten);
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

        public static Key_Usage GetKeyUse(IntPtr keyPointer)
        {
            Key_Usage keyUse;
            uint result;
            Interop.CheckReturnOrThrow(NCryptGetProperty(keyPointer, NCRYPT_KEY_USAGE_PROPERTY,(byte*) &keyUse, 4, out result, 0));
            return keyUse;
        }

        public static int GetSize(IntPtr keyPointer)
        {
            int keyUse;
            uint result;
            Interop.CheckReturnOrThrow(NCryptGetProperty(keyPointer, "Length", (byte*)&keyUse, 4, out result, 0));
            return keyUse;
        }

        public static string GetPrivateKeyAlgo(IntPtr keyPointer)
        {
            string algo;
            uint length;
            NCryptGetProperty(keyPointer, AlgoProperty, null, 0, out length, 0);
            byte* buffer = stackalloc byte[(int)length];
            NCryptGetProperty(keyPointer, AlgoProperty, buffer, length, out length, 0);

            algo = Marshal.PtrToStringUni((IntPtr)buffer);
            return algo;
        }
        [Flags]
        public enum Key_Usage:uint
        {
            NCRYPT_ALLOW_DECRYPT_FLAG = 0x00000001, //The key can be used for decryption.
            NCRYPT_ALLOW_SIGNING_FLAG = 0x00000002, //The key can be used for signing.
            NCRYPT_ALLOW_KEY_AGREEMENT_FLAG = 0x00000004,   //The key can be used for secret agreement encryption.
            NCRYPT_ALLOW_ALL_USAGES = 0x00ffffff,	//The key can be used for any purpose.
        }

        private static T[] GetArrayOfStructs<T>(IntPtr pointerToArray, uint numberOfItems)
        {
            var returnValue = new T[numberOfItems];
            var sizeOfStruct = Marshal.SizeOf<T>();
            for (int i = 0; i < numberOfItems; i++)
            {
                returnValue[i] = Marshal.PtrToStructure<T>(IntPtr.Add(pointerToArray, i * sizeOfStruct));
            }
            NCryptFreeObject(pointerToArray);
            return returnValue;
        }
    }
}
