using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

internal partial class Interop
{
    internal partial class Libeay32
    {
        [StructLayout(LayoutKind.Sequential)]
        internal unsafe struct EC_builtin_curve
        {
            internal int nid;
            internal void* comment;
        }
    }
}
