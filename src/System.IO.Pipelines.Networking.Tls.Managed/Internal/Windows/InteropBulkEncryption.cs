using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using static System.IO.Pipelines.Networking.Tls.Managed.Internal.Windows.InteropStructs;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Windows
{
    internal unsafe static class InteropBulkEncryption
    {
        private const string Dll = "Bcrypt.dll";

        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern ReturnCodes BCryptImportKey(IntPtr hAlgorithm, IntPtr hImportKey, string pszBlobType, out IntPtr phKey, IntPtr pbKeyObject, int cbKeyObject, IntPtr pbInput, int cbInput, int dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern ReturnCodes BCryptDecrypt(IntPtr hKey, void* pbInput, int cbInput, void* pPaddingInfo, void* pbIV, int cbIV, void* pbOutput, int cbOutput, out int pcbResult, int dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern ReturnCodes BCryptEncrypt(IntPtr hKey, void* pbInput, int cbInput, void* pPaddingInfo, void* pbIV, uint cbIV, void* pbOutput, int cbOutput, out int pcbResult, uint dwFlags);

        private static readonly int s_sizeOfKeyHeader = Marshal.SizeOf<BCRYPT_KEY_DATA_BLOB>();

        public unsafe static IntPtr ImportKey(IntPtr provider, Memory<byte> objectBuffer, byte* key, int keyLength)
        {
            void* memPtr;
            if (!objectBuffer.TryGetPointer(out memPtr))
            {
                throw new InvalidOperationException("Cannot get pointer to owned memory!!");
            }

            var keyBlob = stackalloc byte[s_sizeOfKeyHeader + keyLength];
            BCRYPT_KEY_DATA_BLOB* pkeyDataBlob = (BCRYPT_KEY_DATA_BLOB*)keyBlob;
            pkeyDataBlob->dwMagic = KeyBlobMagicNumber.KeyDataBlob;
            pkeyDataBlob->dwVersion = 1;
            pkeyDataBlob->cbKeyData = keyLength;
            var keyBlobSpan = new Span<byte>(keyBlob + s_sizeOfKeyHeader,keyLength);
            var keyDataSpan = new Span<byte>(key, keyLength);
            keyDataSpan.CopyTo(keyBlobSpan);

            IntPtr handle;
            ExceptionHelper.CheckReturnCode(
                BCryptImportKey(provider, IntPtr.Zero, "KeyDataBlob", out handle, (IntPtr)memPtr, objectBuffer.Length,(IntPtr) keyBlob, s_sizeOfKeyHeader + keyLength, 0));
            return handle;
        }
    }
}
