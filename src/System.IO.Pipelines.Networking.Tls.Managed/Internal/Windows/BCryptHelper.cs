using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Windows;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
using static global::Interop.BCrypt;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Windows
{
    internal static class BCryptHelper
    {
        private static readonly BCRYPT_ALGORITHM_IDENTIFIER[] s_hashAlgorithms;
        private static readonly BCRYPT_ALGORITHM_IDENTIFIER[] s_secretAlgorithms;
        private static readonly BCRYPT_ALGORITHM_IDENTIFIER[] s_randomAlgorithms;
        private static readonly BCRYPT_ALGORITHM_IDENTIFIER[] s_asymmetricAlgorithms;
        private static readonly BCRYPT_ALGORITHM_IDENTIFIER[] s_cipherAlgorithms;
        private static readonly BCRYPT_ALGORITHM_IDENTIFIER[] s_signatureAlgorithms;

        static BCryptHelper()
        {
            s_hashAlgorithms = GetAlgos(EnumAlgorithmsFlags.BCRYPT_HASH_OPERATION);
            s_cipherAlgorithms = GetAlgos(EnumAlgorithmsFlags.BCRYPT_CIPHER_OPERATION);
            s_asymmetricAlgorithms = GetAlgos(EnumAlgorithmsFlags.BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION);
            s_signatureAlgorithms = GetAlgos(EnumAlgorithmsFlags.BCRYPT_SIGNATURE_OPERATION);
            s_secretAlgorithms = GetAlgos(EnumAlgorithmsFlags.BCRYPT_SECRET_AGREEMENT_OPERATION);
            s_randomAlgorithms = GetAlgos(EnumAlgorithmsFlags.BCRYPT_RNG_OPERATION);
        }

        private static BCRYPT_ALGORITHM_IDENTIFIER[] GetAlgos(EnumAlgorithmsFlags algoType)
        {
            int sizeOfStruct = Marshal.SizeOf<BCRYPT_ALGORITHM_IDENTIFIER>();
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

        private static SafeBCryptAlgorithmHandle OpenProvider(string provider, BCryptOpenAlgorithmProviderFlags flags, BCRYPT_ALGORITHM_IDENTIFIER[] identifiers)
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
                return null;
            }
            SafeBCryptAlgorithmHandle algoHandle;
            ExceptionHelper.CheckReturnCode(BCryptOpenAlgorithmProvider(out algoHandle, provider, null, flags));
            return algoHandle;
        }
        
        internal unsafe static SafeBCryptKeyHandle ImportKey(SafeBCryptAlgorithmHandle provider, Memory<byte> objectBuffer, byte* key, int keyLength)
        {
            void* memPtr;
            if (!objectBuffer.TryGetPointer(out memPtr))
            {
                throw new InvalidOperationException("Cannot get pointer to owned memory!!");
            }
            var keyBlob = stackalloc byte[sizeof(BCRYPT_KEY_DATA_BLOB) + keyLength];
            BCRYPT_KEY_DATA_BLOB* pkeyDataBlob = (BCRYPT_KEY_DATA_BLOB*)keyBlob;
            pkeyDataBlob->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
            pkeyDataBlob->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
            pkeyDataBlob->cbKeyData = keyLength;
            var keyBlobSpan = new Span<byte>(keyBlob + sizeof(BCRYPT_KEY_DATA_BLOB), keyLength);
            var keyDataSpan = new Span<byte>(key, keyLength);
            keyDataSpan.CopyTo(keyBlobSpan);

            SafeBCryptKeyHandle handle;
            ExceptionHelper.CheckReturnCode(
                BCryptImportKey(provider, null, "KeyDataBlob", out handle, (IntPtr)memPtr, objectBuffer.Length, (IntPtr)keyBlob, sizeof(BCRYPT_KEY_DATA_BLOB) + keyLength, 0));
            return handle;
        }

        internal static SafeBCryptAlgorithmHandle OpenHashProvider(string provider, bool isHmac)
        {
            return OpenProvider(provider, isHmac ? BCryptOpenAlgorithmProviderFlags.BCRYPT_ALG_HANDLE_HMAC_FLAG : 0, s_hashAlgorithms);
        }

        internal static SafeBCryptAlgorithmHandle OpenSecretProvider(string provider)
        {
            return OpenProvider(provider, 0, s_secretAlgorithms);
        }

        internal static SafeBCryptAlgorithmHandle OpenBulkProvider(string provider)
        {
            return OpenProvider(provider, 0, s_cipherAlgorithms);
        }
    }
}
