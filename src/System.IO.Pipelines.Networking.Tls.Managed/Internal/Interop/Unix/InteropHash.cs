using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Unix;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Unix
{
    internal static class InteropHash
    {
        private const string Dll = global::Interop.Libraries.OpenSslCrypto;
        private const int EVP_PKEY_HMAC = 855;

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_sha256();
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_sha384();
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_MD_size(IntPtr hashProvider);
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_DigestUpdate(SafeEvpMdCtxHandle ctx, IntPtr buffer, int bufferLen);
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_DigestFinal_ex(SafeEvpMdCtxHandle ctx, IntPtr buffer, ref int bufferLen);
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static void EVP_MD_CTX_destroy(IntPtr ctx);
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static IntPtr EVP_PKEY_new_mac_key(int keyType, IntPtr engine, IntPtr buffer, int bufferLen);
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_DigestSignFinal(SafeEvpMdCtxHandle ctx, IntPtr buffer, ref int bufferLen);

        public static IntPtr CreateHmacKey(IntPtr buffer, int bufferLen)
        {
            return
                OpenSslPal.CheckPointerError(
                    EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, IntPtr.Zero, buffer, bufferLen));
        }
    }
}
