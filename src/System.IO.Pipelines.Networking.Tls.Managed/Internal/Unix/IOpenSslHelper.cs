using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Unix
{
    internal interface IOpenSslHelper
    {
        void CheckOpenSslError(int returnCode);
        int CheckCtrlForError(int returnCode);
        IntPtr CheckPointerError(IntPtr pointer);
        SafeEvpMdCtxHandle CreateHash(IntPtr hashProvider);
        SafeEvpMdCtxHandle CopyHash(SafeEvpMdCtxHandle original);
        int[] GetCurveNids();
    }
}
