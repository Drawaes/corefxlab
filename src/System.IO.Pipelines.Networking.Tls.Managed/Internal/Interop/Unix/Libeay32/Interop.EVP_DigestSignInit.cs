using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

internal partial class Interop
{
    internal partial class Libeay32
    {
        [DllImport(Libraries.OpenSslCrypto, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int EVP_DigestSignInit(SafeEvpMdCtxHandle ctx, IntPtr engine, IntPtr hashProvider, IntPtr engine2, IntPtr pkey);
    }
}
