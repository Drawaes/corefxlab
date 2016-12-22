using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Unix
{
    internal static class ExceptionHelper
    {
        internal unsafe static void CheckOpenSslError(int returnCode)
        {
            if (returnCode != 1)
            {
                var tempBuffer = new byte[512];
                fixed (byte* buffPointer = tempBuffer)
                {
                    var errCode = InteropCrypto.ERR_get_error();
                    InteropCrypto.ERR_error_string_n(errCode, buffPointer, (UIntPtr)tempBuffer.Length);
                    var errorString = Marshal.PtrToStringAnsi((IntPtr)buffPointer);

                }
                throw new Security.SecurityException($"Ssl Exception {returnCode}");
            }
        }

        internal unsafe static int CheckCtrlForError(int returnCode)
        {
            if (returnCode < 1)
            {
                var tempBuffer = new byte[512];
                fixed (byte* buffPointer = tempBuffer)
                {
                    var errCode = InteropCrypto.ERR_get_error();
                    InteropCrypto.ERR_error_string_n(errCode, buffPointer, (UIntPtr)tempBuffer.Length);
                    var errorString = Marshal.PtrToStringAnsi((IntPtr)buffPointer);
                    throw new Security.SecurityException($"Ssl Exception {errorString}");
                }
            }
            return returnCode;
        }

        internal static IntPtr CheckPointerError(IntPtr pointer)
        {
            if (pointer == IntPtr.Zero)
            {
                throw new Security.SecurityException($"OpenSsl Exception pointer null");
            }
            return pointer;
        }
    }
}
