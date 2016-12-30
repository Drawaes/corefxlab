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
        internal static extern IntPtr EVP_PKEY_CTX_new(IntPtr key, IntPtr engine);
    }
}
