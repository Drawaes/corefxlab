using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Windows
{
    internal static class ExceptionHelper
    {
        internal static void CheckReturnCode(ReturnCodes returnCode)
        {
            if(returnCode != 0)
            {
                throw new InvalidOperationException($"Api Error {returnCode}");
            }
        }
    }
}
