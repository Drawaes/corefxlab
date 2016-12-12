using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.BulkCiphers;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using static System.IO.Pipelines.Networking.Tls.Internal.ManagedTls.InteropStructs;

namespace System.IO.Pipelines.Networking.Tls.Internal.ManagedTls
{
    public unsafe static class InteropProperties
    {
        private const string Dll = "Bcrypt.dll";

        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal extern static ReturnCodes BCryptGetProperty(IntPtr bCryptHandle, string pszProperty, out int pbOutput, int cbOutput, out int pcbResult, uint dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal extern static ReturnCodes BCryptGetProperty(IntPtr bCryptHandle, string pszProperty, void* pbOutput, int cbOutput, out int pcbResult, uint dwFlags);
        [DllImport(Dll, SetLastError = true, ExactSpelling = true, CharSet = CharSet.Unicode)]
        internal static extern ReturnCodes BCryptSetProperty(IntPtr hObject, string pszProperty, string pbInput, int cbInput, uint dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal extern static ReturnCodes BCryptSetProperty(IntPtr hObject, string pszProperty, void* pbInput, int cbInput, uint dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal extern static ReturnCodes BCryptSetProperty(IntPtr bCryptHandle, string pszProperty, ref int pbOutput, int cbOutput, uint dwFlags);

        private const string BCRYPT_OBJECT_LENGTH = "ObjectLength";
        private const string BCRYPT_AUTH_TAG_LENGTH = "AuthTagLength";
        private const string BCRYPT_BLOCK_LENGTH = "BlockLength";
        private const string BCRYPT_CHAINING_MODE = "ChainingMode";
        private const string BCRYPT_KEY_LENGTH = "KeyLength";
        private const string BCRYPT_HASH_LENGTH = "HashDigestLength";
        private const string BCRYPT_HASH_BLOCK_LENGTH = "HashBlockLength";
        private const string BCRYPT_CHAIN_MODE_CBC = "ChainingModeCBC";
        private const string BCRYPT_CHAIN_MODE_GCM = "ChainingModeGCM";
        private const string BCRYPT_PROVIDER_HANDLE = "ProviderHandle";

        public static string GetBlockChainingMode(IntPtr provider)
        {
            return GetStringProperty(provider, BCRYPT_CHAINING_MODE);
        }

        public static BCRYPT_AUTH_TAG_LENGTHS_STRUCT GetAuthTagLengths(IntPtr provider)
        {
            var size = sizeof(BCRYPT_AUTH_TAG_LENGTHS_STRUCT);
            var output = default(BCRYPT_AUTH_TAG_LENGTHS_STRUCT);
            int result;
            BCryptGetProperty(provider, BCRYPT_AUTH_TAG_LENGTH, &output, size, out result, 0);
            return output;
        }

        public static IntPtr GetProviderHandle(IntPtr key)
        {
            var size = IntPtr.Size;
            IntPtr output = IntPtr.Zero;
            int result;
            Interop.CheckReturnOrThrow(BCryptGetProperty(key, BCRYPT_PROVIDER_HANDLE, &output, size, out result, 0));
            return output;
        }
        
        public static void SetBlockChainingMode(IntPtr provider, BulkCipherChainingMode chainingMode)
        {
            string value;
            switch (chainingMode)
            {
                case BulkCipherChainingMode.CBC:
                    value = BCRYPT_CHAIN_MODE_CBC;
                    break;
                case BulkCipherChainingMode.GCM:
                    value = BCRYPT_CHAIN_MODE_GCM;
                    break;
                default:
                    throw new InvalidOperationException($"Unknown chaining mode {chainingMode}");
            }
            SetStringProperty(provider, BCRYPT_CHAINING_MODE, value);
        }

        private static string GetStringProperty(IntPtr provider, string property)
        {
            int length;
            Interop.CheckReturnOrThrow(BCryptGetProperty(provider, property, null, 0, out length, 0));
            string result;
            unsafe
            {
                var temp = stackalloc byte[length];

                Interop.CheckReturnOrThrow(BCryptGetProperty(provider, BCRYPT_CHAINING_MODE, temp, length, out length, 0));
                result = Marshal.PtrToStringUni((IntPtr)temp);
            }
            return result;
        }

        internal static void SetStringProperty(IntPtr provider, string property, string value)
        {
            Interop.CheckReturnOrThrow(
                BCryptSetProperty(provider, property, value,  value != null ? (value.Length + 1) * sizeof(char) : 0, 0));
        }
    
        private static int GetIntProperty(IntPtr provider, string property)
        {
            int length;
            int objectSize;
            Interop.CheckReturnOrThrow(BCryptGetProperty(provider, property, out objectSize, 4, out length, 0));
            return objectSize;
        }

        public static int GetObjectLength(IntPtr provider)
        {
            return GetIntProperty(provider, BCRYPT_OBJECT_LENGTH);
        }
        public static int GetHashLength(IntPtr provider)
        {
            return GetIntProperty(provider, BCRYPT_HASH_LENGTH);
        }
        public static int GetBlockLength(IntPtr provider)
        {
            return GetIntProperty(provider, BCRYPT_BLOCK_LENGTH);
        }
        public static int GetAdditionalTagLength(IntPtr provider)
        {
            return GetIntProperty(provider, BCRYPT_AUTH_TAG_LENGTH);
        }
        public static int GetHashBlockLength(IntPtr provider)
        {
            return GetIntProperty(provider, BCRYPT_HASH_BLOCK_LENGTH);
        }
        public static int GetKeySizeInBits(IntPtr provider)
        {
            return GetIntProperty(provider, BCRYPT_KEY_LENGTH);
        }
    }
}
