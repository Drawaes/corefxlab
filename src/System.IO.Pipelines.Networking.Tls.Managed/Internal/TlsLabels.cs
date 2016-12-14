using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal
{
    internal static class TlsLabels
    {
        private const string MASTER_SECRET = "master secret";
        internal static readonly IntPtr MasterSecretPointer = Marshal.StringToHGlobalAnsi(MASTER_SECRET);
        internal static readonly int MasterSecretSize = MASTER_SECRET.Length;
        //private static readonly IntPtr s_label_KeyExpansion = Marshal.StringToHGlobalAnsi("extended master secret");
    }
}
