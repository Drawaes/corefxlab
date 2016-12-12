using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Internal.ManagedTls
{
    public unsafe static class InteropPki
    {
        private const string Dll = "Bcrypt.dll";
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern ReturnCodes BCryptExportKey(IntPtr hKey, IntPtr encyrptKey, string blobType, IntPtr pbOutput, int cbOutput, out int pcbResult, uint dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern ReturnCodes BCryptImportKeyPair(IntPtr hAlgorithm, IntPtr hImportKey, string pszBlobType, out IntPtr phKey, IntPtr pbInput, int cbInput, uint dwFlags);

        private const string NCRYPT_ALGORITHM_PROPERTY = "Algorithm Name";


        internal const string BCRYPT_DH_PUBLIC_BLOB = "DHPUBLICBLOB";
        internal const string BCRYPT_ECCPUBLIC_BLOB = "ECCPUBLICBLOB";
        internal const uint CRYPT_DO_NOT_FINALIZE_FLAG = 0x400;
        
        public enum Padding : uint
        {
            NONE = 0,
            BCRYPT_PAD_PKCS1 = 0x02,
            BCRYPT_PAD_PSS = 0x00000008,
            BCRYPT_PAD_PKCS1_OPTIONAL_HASH_OID  =0x00000010 
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct BCRYPT_PKCS1_PADDING_INFO
        {
            /// <summary>
            ///     Null-terminated Unicode string that identifies the hashing algorithm used to create the padding.
            /// </summary>
            internal IntPtr pszAlgId;
        }

    }
}
