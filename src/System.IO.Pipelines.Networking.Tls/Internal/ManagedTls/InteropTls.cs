using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Internal.ManagedTls
{
    public static class InteropTls
    {
        private const string Dll = "Ncrypt.dll";

        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal extern static ReturnCodes SslEnumProtocolProviders(out uint pAlgCount, out IntPtr algoArray, uint notUsed);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal extern static ReturnCodes SslFreeBuffer(IntPtr pvInput);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal extern static ReturnCodes SslOpenProvider(out IntPtr phSslProvider, string pszProviderName,uint dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal extern static ReturnCodes SslSignHash(IntPtr hSslProvider,IntPtr hPrivateKey,IntPtr pbHashValue,int cbHashValue,IntPtr pbSignature,int cbSignature,out int pcbResult,int dwFlags);

        private readonly static IntPtr _sslProvider;

        static InteropTls()
        {
            IntPtr output;
            Interop.CheckReturnOrThrow(SslOpenProvider(out output, null,0));
            _sslProvider = output;
        }

        internal static ReturnCodes SslSignHash(IntPtr hPrivateKey, IntPtr pbHashValue, int cbHashValue, IntPtr pbSignature, int cbSignature, out int pcbResult) => SslSignHash(_sslProvider, hPrivateKey, pbHashValue, cbHashValue, pbSignature, cbSignature, out pcbResult, 0);
        
        internal struct NCryptProviderName
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pszName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pszComment;
        }

        internal static readonly NCryptProviderName[] Providers = GetProviders();

        private static NCryptProviderName[] GetProviders()
        {
            int sizeOfStruct = Unsafe.SizeOf<NCryptProviderName>();
            uint number;
            IntPtr algoArray;
            Interop.CheckReturnOrThrow(SslEnumProtocolProviders(out number, out algoArray, 0));
            var returnValues = new NCryptProviderName[number];
            for (int i = 0; i < number; i++)
            {
                var newPointer = IntPtr.Add(algoArray, i * sizeOfStruct);
                var firstAlgo = Marshal.PtrToStructure<NCryptProviderName>(newPointer);
                returnValues[i] = firstAlgo;
            }
            SslFreeBuffer(algoArray);
            return returnValues;
        }

    }
}
