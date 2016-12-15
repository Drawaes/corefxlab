using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.BulkCipher;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using static System.IO.Pipelines.Networking.Tls.Managed.Internal.Windows.InteropStructs;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Windows
{
    internal unsafe static class InteropProperties
    {
        private const string Dll = "Bcrypt.dll";
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
        private const string BCRYPT_ECC_CURVE_NAME_LIST = "ECCCurveNameList";
        private const string BCRYPT_ECC_CURVE_NAME = "ECCCurveName";
        
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private extern static ReturnCodes BCryptGetProperty(IntPtr bCryptHandle, string pszProperty, out int pbOutput, int cbOutput, out int pcbResult, uint dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private extern static ReturnCodes BCryptSetProperty(IntPtr hObject, string pszProperty, void* pbInput, int cbInput, uint dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private extern static ReturnCodes BCryptSetProperty(IntPtr bCryptHandle, string pszProperty, ref int pbOutput, int cbOutput, uint dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private extern static ReturnCodes BCryptGetProperty(IntPtr bCryptHandle, string pszProperty, void* pbOutput, int cbOutput, out int pcbResult, uint dwFlags);
        [DllImport(Dll, SetLastError = true, ExactSpelling = true, CharSet = CharSet.Unicode)]
        private static extern ReturnCodes BCryptSetProperty(IntPtr hObject, string pszProperty, string pbInput, int cbInput, uint dwFlags);

        public static int GetObjectLength(IntPtr provider)
        {
            return GetIntProperty(provider, BCRYPT_OBJECT_LENGTH);
        }

        public static BCRYPT_AUTH_TAG_LENGTHS_STRUCT GetAuthTagLengths(IntPtr provider)
        {
            var size = sizeof(BCRYPT_AUTH_TAG_LENGTHS_STRUCT);
            var output = default(BCRYPT_AUTH_TAG_LENGTHS_STRUCT);
            int result;
            BCryptGetProperty(provider, BCRYPT_AUTH_TAG_LENGTH, &output, size, out result, 0);
            return output;
        }

        public static int GetMaxAuthTagLength(IntPtr provider)
        {
            return GetAuthTagLengths(provider).dwMaxLength;
        }

        public static int GetBlockLength(IntPtr provider)
        {
            return GetIntProperty(provider, BCRYPT_BLOCK_LENGTH);
        }

        public static int GetHashLength(IntPtr provider)
        {
            return GetIntProperty(provider, BCRYPT_HASH_LENGTH);
        }

        public static int GetKeySizeInBits(IntPtr provider)
        {
            return GetIntProperty(provider, BCRYPT_KEY_LENGTH);
        }

        public static void SetEccCurveName(IntPtr key, string curveName)
        {
            SetStringProperty(key, BCRYPT_ECC_CURVE_NAME, curveName);
        }

        private static int GetIntProperty(IntPtr provider, string property)
        {
            int length;
            int objectSize;
            ExceptionHelper.CheckReturnCode(BCryptGetProperty(provider, property, out objectSize, 4, out length, 0));
            return objectSize;
        }

        private static void SetStringProperty(IntPtr provider, string property, string value)
        {
            ExceptionHelper.CheckReturnCode(
                BCryptSetProperty(provider, property, value, value != null ? (value.Length + 1) * sizeof(char) : 0, 0));
        }

        private static string[] GetStringArrayProperty(IntPtr provider, string property)
        {
            int bufferSize;
            ExceptionHelper.CheckReturnCode(BCryptGetProperty(provider, property, null, 0, out bufferSize, 0));
            var tempBuffer = stackalloc byte[bufferSize];
            ExceptionHelper.CheckReturnCode(BCryptGetProperty(provider, property, tempBuffer, bufferSize, out bufferSize,0));
            var header = Marshal.PtrToStructure<InteropStructs.BasicPointerArray>((IntPtr)tempBuffer);
            var returnValues = new string[header.Count];
            for (var i = 0; i < header.Count;i++)
            {
                var currentPtr = Unsafe.Read<IntPtr>((void*) IntPtr.Add(header.PointerToFirstItem, i * IntPtr.Size));
                returnValues[i] = Marshal.PtrToStringUni(currentPtr);
            }
            return returnValues;
        }

        public static string[] GetECCurveNameList(IntPtr provider)
        {
            return GetStringArrayProperty(provider, BCRYPT_ECC_CURVE_NAME_LIST);
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


    }
}
