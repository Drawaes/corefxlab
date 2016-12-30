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
        internal static extern void CRYPTO_set_locking_callback(locking_function lockingFunction);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal unsafe delegate void locking_function(LockState mode, int threadNumber, byte* file, int line);

        [Flags]
        internal enum LockState
        {
            CRYPTO_UNLOCK = 0x02,
            CRYPTO_READ = 0x04,
            CRYPTO_LOCK = 0x01,
            CRYPTO_WRITE = 0x08,
        }
    }
}
