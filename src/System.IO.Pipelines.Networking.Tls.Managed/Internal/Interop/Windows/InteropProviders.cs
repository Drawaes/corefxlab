using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Windows
{
    internal static unsafe class InteropProviders
    {
        private const string Dll = "Bcrypt.dll";
        private const uint BCRYPT_ALG_HANDLE_HMAC_FLAG = 8;
        private const uint BCRYPT_HASH_REUSABLE_FLAG = 0x00000020;

        private static readonly BCRYPT_ALGORITHM_IDENTIFIER[] HashAlgorithms;
        private static readonly BCRYPT_ALGORITHM_IDENTIFIER[] SecretAlgorithms;
        private static readonly BCRYPT_ALGORITHM_IDENTIFIER[] RandomAlgorithms;
        private static readonly BCRYPT_ALGORITHM_IDENTIFIER[] AsymmetricAlgorithms;
        private static readonly BCRYPT_ALGORITHM_IDENTIFIER[] CipherAlgorithms;
        private static readonly BCRYPT_ALGORITHM_IDENTIFIER[] SignatureAlgorithms;

        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private extern static NTResult BCryptEnumAlgorithms(EnumAlgorithmsOptions dwAlgOperations, out uint pAlgCount, out IntPtr algoArray, uint dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private extern static void BCryptFreeBuffer(IntPtr pointer);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private extern static NTResult BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm, string pszAlgId, string pszImplementation, uint dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private extern static NTResult BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint dwFlags);

        [StructLayout(LayoutKind.Sequential)]
        private struct BCRYPT_ALGORITHM_IDENTIFIER
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

        [Flags]
        private enum EnumAlgorithmsOptions : uint
        {
            BCRYPT_CIPHER_OPERATION = 0x00000001, // Include the cipher algorithms in the enumeration.
            BCRYPT_HASH_OPERATION = 0x00000002, // Include the hash algorithms in the enumeration.
            BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION = 0x00000004, //Include the asymmetric encryption algorithms in the enumeration.
            BCRYPT_SECRET_AGREEMENT_OPERATION = 0x00000008, // Include the secret agreement algorithms in the enumeration.
            BCRYPT_SIGNATURE_OPERATION = 0x00000010, // Include the signature algorithms in the enumeration.
            BCRYPT_RNG_OPERATION = 0x00000020, // Include the random number generator (RNG) algorithms in the enumeration.
        }

        static InteropProviders()
        {
            HashAlgorithms = GetAlgos(EnumAlgorithmsOptions.BCRYPT_HASH_OPERATION);
            CipherAlgorithms = GetAlgos(EnumAlgorithmsOptions.BCRYPT_CIPHER_OPERATION);
            AsymmetricAlgorithms = GetAlgos(EnumAlgorithmsOptions.BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION);
            SignatureAlgorithms = GetAlgos(EnumAlgorithmsOptions.BCRYPT_SIGNATURE_OPERATION);
            SecretAlgorithms = GetAlgos(EnumAlgorithmsOptions.BCRYPT_SECRET_AGREEMENT_OPERATION);
            RandomAlgorithms = GetAlgos(EnumAlgorithmsOptions.BCRYPT_RNG_OPERATION);
        }

        private static BCRYPT_ALGORITHM_IDENTIFIER[] GetAlgos(EnumAlgorithmsOptions algoType)
        {
            int sizeOfStruct = Unsafe.SizeOf<BCRYPT_ALGORITHM_IDENTIFIER>();
            uint number;
            IntPtr algoArray;
            ExceptionHelper.CheckReturnCode(BCryptEnumAlgorithms(algoType, out number, out algoArray, 0));
            try
            {
                var returnValues = new BCRYPT_ALGORITHM_IDENTIFIER[number];
                for (int i = 0; i < number; i++)
                {
                    var newPointer = IntPtr.Add(algoArray, i * sizeOfStruct);
                    var firstAlgo = Marshal.PtrToStructure<BCRYPT_ALGORITHM_IDENTIFIER>(newPointer);
                    returnValues[i] = firstAlgo;
                }
                return returnValues;
            }
            finally
            {
                BCryptFreeBuffer(algoArray);
            }
        }

        internal static void CloseProvider(IntPtr provider)
        {
            ExceptionHelper.CheckReturnCode(BCryptCloseAlgorithmProvider(provider, 0));
        }

        internal static IntPtr OpenHashProvider(string provider, bool isHmac)
        {
            return OpenProvider(provider, isHmac ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0, HashAlgorithms);
        }

        private static IntPtr OpenProvider(string provider, uint flags, BCRYPT_ALGORITHM_IDENTIFIER[] identifiers)
        {
            var isValid = false;
            for (int i = 0; i < identifiers.Length; i++)
            {
                if (identifiers[i].pszName == provider)
                {
                    isValid = true;
                    break;
                }
            }
            if (!isValid)
            {
                return IntPtr.Zero;
            }
            IntPtr provPtr;
            ExceptionHelper.CheckReturnCode(
                BCryptOpenAlgorithmProvider(out provPtr, provider, null, flags));
            return provPtr;
        }

        public static IntPtr OpenSecretProvider(string provider)
        {
            return OpenProvider(provider, 0, SecretAlgorithms);
        }

        internal static IntPtr OpenBulkProvider(string provider)
        {
            return OpenProvider(provider, 0, CipherAlgorithms);
        }
    }
}