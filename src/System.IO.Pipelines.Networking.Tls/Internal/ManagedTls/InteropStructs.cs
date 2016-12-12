using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Internal.ManagedTls
{
    public class InteropStructs
    {
        internal enum KeyBlobMagicNumber
        {
            RsaPublic = 0x31415352,                                     // BCRYPT_RSAPUBLIC_MAGIC
            RsaPrivate = 0x32415352,                                    // BCRYPT_RSAPRIVATE_MAGIC
            KeyDataBlob = 0x4d42444b,                                   // BCRYPT_KEY_DATA_BLOB_MAGIC
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct BCRYPT_KEY_DATA_BLOB
        {
            internal KeyBlobMagicNumber dwMagic;
            internal int dwVersion;
            internal int cbKeyData;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct BCRYPT_ECCKEY_BLOB
        {
            public uint dwMagic;
            public int cbKey;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct BCRYPT_AUTH_TAG_LENGTHS_STRUCT
        {
            public int dwMinLength;
            public int dwMaxLength;
            public int dwIncrement;
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

        [Flags]
        internal enum AuthenticatedCipherModeInfoFlags : uint
        {
            None = 0x00000000,
            ChainCalls = 0x00000001,                           // BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG
            InProgress = 0x00000002,                           // BCRYPT_AUTH_MODE_IN_PROGRESS_FLAG
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct NCryptKeyName
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pszName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pszAlgid;
            public uint dwLegacyKeySpec;
            public uint dwFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct NCryptProviderName
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pszName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pszComment;
        }
    }
}
