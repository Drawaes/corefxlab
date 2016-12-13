using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

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

        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal extern static ReturnCodes BCryptGetProperty(IntPtr bCryptHandle, string pszProperty, out int pbOutput, int cbOutput, out int pcbResult, uint dwFlags);

        public static int GetObjectLength(IntPtr provider)
        {
            return GetIntProperty(provider, BCRYPT_OBJECT_LENGTH);
        }

        public static int GetHashLength(IntPtr provider)
        {
            return GetIntProperty(provider, BCRYPT_HASH_LENGTH);
        }
        
        private static int GetIntProperty(IntPtr provider, string property)
        {
            int length;
            int objectSize;
            ExceptionHelper.CheckReturnCode(BCryptGetProperty(provider, property, out objectSize, 4, out length, 0));
            return objectSize;
        }
    }
}
