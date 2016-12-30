using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using static global::Interop.Libeay32;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Unix
{
    internal partial class OpenSslPal
    {
        private partial class OpenSsl1Pal : IOpenSslHelper
        {
            public unsafe void CheckOpenSslError(int returnCode)
            {
                if (returnCode != 1)
                {
                    var tempBuffer = new byte[512];
                    fixed (byte* buffPointer = tempBuffer)
                    {
                        var errCode = ERR_get_error();
                        ERR_error_string_n(errCode, buffPointer, (UIntPtr)tempBuffer.Length);
                        var errorString = Marshal.PtrToStringAnsi((IntPtr)buffPointer);

                    }
                    throw new Security.SecurityException($"Ssl Exception {returnCode}");
                }
            }
            public unsafe int CheckCtrlForError(int returnCode)
            {
                if (returnCode < 1)
                {
                    var tempBuffer = new byte[512];
                    fixed (byte* buffPointer = tempBuffer)
                    {
                        var errCode = ERR_get_error();
                        ERR_error_string_n(errCode, buffPointer, (UIntPtr)tempBuffer.Length);
                        var errorString = Marshal.PtrToStringAnsi((IntPtr)buffPointer);
                        throw new Security.SecurityException($"Ssl Exception {errorString}");
                    }
                }
                return returnCode;
            }
            public IntPtr CheckPointerError(IntPtr pointer)
            {
                if (pointer == IntPtr.Zero)
                {
                    throw new Security.SecurityException($"OpenSsl Exception pointer null");
                }
                return pointer;
            }
        }
    }
}
