using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Windows
{
    internal unsafe static class InteropStructs
    {
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
        public struct BCRYPT_AUTH_TAG_LENGTHS_STRUCT
        {
            public int dwMinLength;
            public int dwMaxLength;
            public int dwIncrement;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct BCRYPT_KEY_DATA_BLOB
        {
            internal KeyBlobMagicNumber dwMagic;
            internal int dwVersion;
            internal int cbKeyData;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct BCryptBufferDesc
        {
            public uint ulVersion;
            public int cBuffers;
            public IntPtr pBuffers;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct BCryptBuffer
        {
            public int cbBuffer;             // Length of buffer, in bytes
            public BufferTypes BufferType;           // Buffer type
            public void* pvBuffer;             // Pointer to buffer
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct BCRYPT_ECCKEY_BLOB
        {
            public KeyBlobMagicNumber dwMagic;
            public int cbKey;
        }

        internal enum KeyBlobMagicNumber:uint
        {
            RsaPublic = 0x31415352,    // BCRYPT_RSAPUBLIC_MAGIC
            RsaPrivate = 0x32415352,   // BCRYPT_RSAPRIVATE_MAGIC
            KeyDataBlob = 0x4d42444b,  // BCRYPT_KEY_DATA_BLOB_MAGIC
            EchdPublic = 0x504B4345,   //BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC    0x504B4345
        }

        internal enum BufferTypes : uint
        {
            KDF_HASH_ALGORITHM = 0x0,
            KDF_SECRET_PREPEND = 0x1,
            KDF_SECRET_APPEND = 0x2,
            KDF_HMAC_KEY = 0x3,
            KDF_TLS_PRF_LABEL = 0x4,
            KDF_TLS_PRF_SEED = 0x5,
            KDF_SECRET_HANDLE = 0x6,
            KDF_TLS_PRF_PROTOCOL = 0x7,
            KDF_ALGORITHMID = 0x8,
            KDF_PARTYUINFO = 0x9,
            KDF_PARTYVINFO = 0xA,
            KDF_SUPPPUBINFO = 0xB,
            KDF_SUPPPRIVINFO = 0xC,
            KDF_LABEL = 0xD,
            KDF_CONTEXT = 0xE,
            KDF_SALT = 0xF,
            KDF_ITERATION_COUNT = 0x10,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct BasicPointerArray
        {
            public int Count;
            public IntPtr PointerToFirstItem;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct BCRYPT_PKCS1_PADDING_INFO
        {
            internal IntPtr pszAlgId;
        }
    }
}
