using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.BulkCiphers;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Internal.ManagedTls
{
    public unsafe class Interop
    {
        private const string Dll = "Bcrypt.dll";

        public static readonly BCRYPT_ALGORITHM_IDENTIFIER[] HashAlgorithms;
        public static readonly BCRYPT_ALGORITHM_IDENTIFIER[] SecretAlgorithms;
        public static readonly BCRYPT_ALGORITHM_IDENTIFIER[] RandomAlgorithms;
        public static readonly BCRYPT_ALGORITHM_IDENTIFIER[] AsymmetricAlgorithms;
        public static readonly BCRYPT_ALGORITHM_IDENTIFIER[] CipherAlgorithms;
        public static readonly BCRYPT_ALGORITHM_IDENTIFIER[] SignatureAlgorithms;

        internal const uint BCRYPT_ALG_HANDLE_HMAC_FLAG = 8;


        [Flags]
        public enum EnumAlgorithmsOptions
        {
            BCRYPT_CIPHER_OPERATION = 0x00000001, // Include the cipher algorithms in the enumeration.
            BCRYPT_HASH_OPERATION = 0x00000002, // Include the hash algorithms in the enumeration.
            BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION = 0x00000004, //Include the asymmetric encryption algorithms in the enumeration.
            BCRYPT_SECRET_AGREEMENT_OPERATION = 0x00000008, // Include the secret agreement algorithms in the enumeration.
            BCRYPT_SIGNATURE_OPERATION = 0x00000010, // Include the signature algorithms in the enumeration.
            BCRYPT_RNG_OPERATION = 0x00000020, // Include the random number generator (RNG) algorithms in the enumeration.
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct BCRYPT_ALGORITHM_IDENTIFIER
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pszName;
            public uint dwClass;
            public uint dwFlags;

            public override string ToString()
            {
                return pszName;
            }
        }

        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal extern static ReturnCodes BCryptEnumAlgorithms(EnumAlgorithmsOptions dwAlgOperations, out uint pAlgCount, out IntPtr algoArray, uint notUsed);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal extern static void BCryptFreeBuffer(IntPtr pointer);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal extern static ReturnCodes BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm,
            [MarshalAs(UnmanagedType.LPWStr)] string pszAlgId, [MarshalAs(UnmanagedType.LPWStr)] string pszImplementation, uint dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal extern static ReturnCodes BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint dwFlags);

        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal extern static ReturnCodes BCryptCreateHash(IntPtr hAlgorithm, out IntPtr phHash, void* stateBuffer, int hashBufferLength, void* secretBuffer, int secretLength, uint dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal extern static ReturnCodes BCryptHashData(IntPtr hashHandle, void* inputBuffer, int inputLength, uint dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal extern static ReturnCodes BCryptDestroyHash(IntPtr hashHandle);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal extern static ReturnCodes BCryptFinishHash(IntPtr hHash, void* pbOutput, int cbOutput, uint dwFlags);

        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal extern static ReturnCodes BCryptHash(IntPtr hAlgorithm, void* pbSecret, int cbSecret, void* pbInput, int cbInput, void* pbOutput, int cbOutput);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true)]
        internal static extern ReturnCodes BCryptImportKey(IntPtr hAlgorithm, IntPtr hImportKey, [MarshalAs(UnmanagedType.LPWStr)] string pszBlobType, [Out] out IntPtr phKey, [In, Out] IntPtr pbKeyObject, int cbKeyObject, [In, MarshalAs(UnmanagedType.LPArray)] byte[] pbInput, int cbInput, int dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true)]
        internal static extern ReturnCodes BCryptImportKey(IntPtr hAlgorithm, IntPtr hImportKey, [MarshalAs(UnmanagedType.LPWStr)] string pszBlobType, [Out] out IntPtr phKey, [In, Out] IntPtr pbKeyObject, int cbKeyObject, IntPtr pbInput, int cbInput, int dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern ReturnCodes BCryptDecrypt(IntPtr hKey, [In, MarshalAs(UnmanagedType.LPArray)] byte[] pbInput,
                                                           int cbInput, [In, Out] ref InteropStructs.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo,
                                                           [In, Out, MarshalAs(UnmanagedType.LPArray)] byte[] pbIV,
                                                           int cbIV, [Out, MarshalAs(UnmanagedType.LPArray)] byte[] pbOutput,
                                                           int cbOutput, [Out] out int pcbResult, int dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern ReturnCodes BCryptDecrypt(IntPtr hKey, void* pbInput, int cbInput, void* pPaddingInfo, void* pbIV, int cbIV, void* pbOutput, int cbOutput, out int pcbResult, int dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern ReturnCodes BCryptEncrypt(IntPtr hKey, void* pbInput, int cbInput, void* pPaddingInfo, void* pbIV, uint cbIV, void* pbOutput, int cbOutput, out int pcbResult, uint dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern ReturnCodes BCryptGenerateKeyPair(IntPtr hAlgorithm, out IntPtr phKey, int dwLength, int dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern ReturnCodes BCryptFinalizeKeyPair(IntPtr hKey, uint dwFlags);

        static Interop()
        {
            HashAlgorithms = GetAlgos(EnumAlgorithmsOptions.BCRYPT_HASH_OPERATION);
            CipherAlgorithms = GetAlgos(EnumAlgorithmsOptions.BCRYPT_CIPHER_OPERATION);
            AsymmetricAlgorithms = GetAlgos(EnumAlgorithmsOptions.BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION);
            SignatureAlgorithms = GetAlgos(EnumAlgorithmsOptions.BCRYPT_SIGNATURE_OPERATION);
            SecretAlgorithms = GetAlgos(EnumAlgorithmsOptions.BCRYPT_SECRET_AGREEMENT_OPERATION);
            RandomAlgorithms = GetAlgos(EnumAlgorithmsOptions.BCRYPT_RNG_OPERATION);
        }

        //public static void SetKeySize(IntPtr provider, int keySizeInBits)
        //{
        //    CheckReturnOrThrow(BCryptSetProperty(provider, BCRYPT_KEY_LENGTH, keySizeInBits, 4, 0));
        //}

        private static BCRYPT_ALGORITHM_IDENTIFIER[] GetAlgos(EnumAlgorithmsOptions algoType)
        {
            int sizeOfStruct = Unsafe.SizeOf<BCRYPT_ALGORITHM_IDENTIFIER>();
            uint number;
            IntPtr algoArray;
            CheckReturnOrThrow(BCryptEnumAlgorithms(algoType, out number, out algoArray, 0));
            var returnValues = new BCRYPT_ALGORITHM_IDENTIFIER[number];
            for (int i = 0; i < number; i++)
            {
                var newPointer = IntPtr.Add(algoArray, i * sizeOfStruct);
                var firstAlgo = Marshal.PtrToStructure<BCRYPT_ALGORITHM_IDENTIFIER>(newPointer);
                returnValues[i] = firstAlgo;
            }
            BCryptFreeBuffer(algoArray);
            return returnValues;
        }

        public static void CheckReturnOrThrow(ReturnCodes returnValue)
        {
            if (returnValue != ReturnCodes.STATUS_SUCCESS)
            {
                throw new InvalidOperationException($"Error status was {returnValue}");
            }
        }
    }
}
