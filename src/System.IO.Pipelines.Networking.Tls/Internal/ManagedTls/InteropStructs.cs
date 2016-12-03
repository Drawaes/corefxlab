using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Internal.ManagedTls
{
    public class InteropStructs
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct NCryptKeyName
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pszName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pszAlgid;
            public uint dwLegacyKeySpec;
            public uint dwFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct NCryptProviderName
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pszName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pszComment;
        }
    }
}
