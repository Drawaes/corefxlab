using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

internal partial class Interop
{
    internal partial class Libeay32
    {
        [DllImport(Libraries.OpenSslCrypto, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr BIO_s_mem();

        internal static readonly IntPtr BIO_s_mem_type = BIO_s_mem();
    }
}
