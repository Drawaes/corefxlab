using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

internal partial class Interop
{
    internal partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        internal static extern unsafe int OPENSSL_init_crypto(ulong opts, void* settings);
    }
}
