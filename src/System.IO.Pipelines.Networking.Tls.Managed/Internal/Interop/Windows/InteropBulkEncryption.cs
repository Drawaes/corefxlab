using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Windows
{
    internal unsafe static class InteropBulkEncryption
    {
        private const string Dll = "Bcrypt.dll";
        private const uint BCRYPT_KEY_DATA_BLOB_MAGIC = 0x4d42444b;

        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern NTResult BCryptImportKey(IntPtr hAlgorithm, IntPtr hImportKey, string pszBlobType, out IntPtr phKey, IntPtr pbKeyObject, int cbKeyObject, IntPtr pbInput, int cbInput, int dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern NTResult BCryptDestroyKey(IntPtr hKey);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern NTResult BCryptDecrypt(IntPtr hKey, void* pbInput, int cbInput, ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo, void* pbIV, int cbIV, void* pbOutput, int cbOutput, out int pcbResult, uint dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern NTResult BCryptEncrypt(IntPtr hKey, void* pbInput, int cbInput, void* pPaddingInfo, void* pbIV, uint cbIV, void* pbOutput, int cbOutput, out int pcbResult, uint dwFlags);

        private static readonly int s_sizeOfKeyHeader = Marshal.SizeOf<BCRYPT_KEY_DATA_BLOB>();

        [StructLayout(LayoutKind.Sequential)]
        private struct BCRYPT_KEY_DATA_BLOB
        {
            internal uint dwMagic;
            internal int dwVersion;
            internal int cbKeyData;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
        {
            internal int cbSize;
            internal int dwInfoVersion;
            internal IntPtr pbNonce;            // byte * //16
            internal int cbNonce;
            internal IntPtr pbAuthData;         // byte * //28
            internal int cbAuthData;
            internal IntPtr pbTag;              // byte * //40
            internal int cbTag;
            internal IntPtr pbMacContext;       // byte *
            internal int cbMacContext;
            internal int cbAAD;
            internal long cbData;
            internal AuthenticatedCipherModeInfoFlags dwFlags;
        }

        internal static void DestroyKey(IntPtr handle)
        {
            ExceptionHelper.CheckReturnCode(BCryptDestroyKey(handle));
        }

        public static IntPtr ImportKey(IntPtr provider, Memory<byte> objectBuffer, byte* key, int keyLength)
        {
            void* memPtr;
            if (!objectBuffer.TryGetPointer(out memPtr))
            {
                throw new InvalidOperationException("Cannot get pointer to owned memory!!");
            }

            var keyBlob = stackalloc byte[s_sizeOfKeyHeader + keyLength];
            BCRYPT_KEY_DATA_BLOB* pkeyDataBlob = (BCRYPT_KEY_DATA_BLOB*)keyBlob;
            pkeyDataBlob->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
            pkeyDataBlob->dwVersion = 1;
            pkeyDataBlob->cbKeyData = keyLength;
            var keyBlobSpan = new Span<byte>(keyBlob + s_sizeOfKeyHeader, keyLength);
            var keyDataSpan = new Span<byte>(key, keyLength);
            keyDataSpan.CopyTo(keyBlobSpan);

            IntPtr handle;
            ExceptionHelper.CheckReturnCode(
                BCryptImportKey(provider, IntPtr.Zero, "KeyDataBlob", out handle, (IntPtr)memPtr, objectBuffer.Length, (IntPtr)keyBlob, s_sizeOfKeyHeader + keyLength, 0));
            return handle;
        }

        [Flags]
        internal enum AuthenticatedCipherModeInfoFlags : uint
        {
            None = 0x00000000,
            ChainCalls = 0x00000001,                           // BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG
            InProgress = 0x00000002,                           // BCRYPT_AUTH_MODE_IN_PROGRESS_FLAG
        }
    }
}
