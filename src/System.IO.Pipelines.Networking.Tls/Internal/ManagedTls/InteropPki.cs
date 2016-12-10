using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Internal.ManagedTls
{
    public static class InteropPki
    {
        private const string Dll = "Bcrypt.dll";
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern ReturnCodes BCryptExportKey(IntPtr hKey, IntPtr encyrptKey, string blobType, IntPtr pbOutput, int cbOutput, out uint pcbResult, uint dwFlags);

        internal const string BCRYPT_DH_PUBLIC_BLOB = "DHPUBLICBLOB";
    }
}
