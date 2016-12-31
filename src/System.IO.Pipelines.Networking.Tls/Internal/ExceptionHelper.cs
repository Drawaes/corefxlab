using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Internal
{
    internal static class ExceptionHelper
    {
        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static void ThrowException(Exception ex)
        {
            throw ex;
        }
    }
}
