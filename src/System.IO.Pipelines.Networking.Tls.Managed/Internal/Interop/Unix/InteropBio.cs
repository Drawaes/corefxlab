using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Unix
{
    internal unsafe class InteropBio
    {
        private const string CryptoDll = "libeay32.dll";
        [DllImport(CryptoDll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static IntPtr BIO_new(IntPtr type);
        [DllImport(CryptoDll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static IntPtr BIO_s_mem();
        [DllImport(CryptoDll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static void BIO_free(IntPtr bio);
        [DllImport(CryptoDll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static int BIO_write(IntPtr bio, byte* buf, int len);
    }
}
