using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Unix
{
    internal partial class OpenSslPal
    {
        private class OpenSsl11Helper : IOpenSslHelper
        {
            public int CheckCtrlForError(int returnCode)
            {
                throw new NotImplementedException();
            }

            public void CheckOpenSslError(int returnCode)
            {
                throw new NotImplementedException();
            }

            public IntPtr CheckPointerError(IntPtr pointer)
            {
                throw new NotImplementedException();
            }

            public SafeEvpMdCtxHandle CopyHash(SafeEvpMdCtxHandle original)
            {
                throw new NotImplementedException();
            }

            public SafeEvpMdCtxHandle CreateHash(IntPtr hashProvider)
            {
                throw new NotImplementedException();
            }

            public int[] GetCurveNids()
            {
                throw new NotImplementedException();
            }
        }
    }
}
