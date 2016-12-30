using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
using static global::Interop.Libeay32;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Unix
{
    internal partial class OpenSslPal
    {
        private partial class OpenSsl1Pal : IOpenSslHelper
        {
            public SafeEvpMdCtxHandle CreateHash(IntPtr hashProvider)
            {
                var hash = EVP_MD_CTX_create();
                CheckOpenSslError(EVP_DigestInit_ex(hash, hashProvider, IntPtr.Zero));
                return hash;
            }

            public SafeEvpMdCtxHandle CopyHash(SafeEvpMdCtxHandle original)
            {
                var tmp = EVP_MD_CTX_create();
                CheckOpenSslError(EVP_MD_CTX_copy_ex(tmp, original));
                return tmp;
            }
        }
    }
}
