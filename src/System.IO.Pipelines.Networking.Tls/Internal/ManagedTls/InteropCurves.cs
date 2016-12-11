using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.KeyExchange;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Internal.ManagedTls
{
    public class InteropCurves
    {
        private static readonly List<string> _availableCurves = new List<string>() {
            "secP160k1", "secP160r1", "secP160r2", "secP192k1", "secP192r1", "secP224k1",
            "secP224r1", "secP256k1", "secP256r1", "secP384r1", "secP521r1"};

        private const string BCRYPT_ECC_CURVE_NAME_LIST = "ECCCurveNameList";
        private const string BCRYPT_ECC_CURVE_NAME = "ECCCurveName";

        public static string MapTlsCurve(EllipticCurves exchange)
        {
            if (_availableCurves.Contains(exchange.ToString(), StringComparer.OrdinalIgnoreCase))
            {
                return exchange.ToString();
            }
            return null;
        }

        public static void SetEccCurveName(IntPtr key, string curveName)
        {
            InteropProperties.SetStringProperty(key, BCRYPT_ECC_CURVE_NAME, curveName );
        }

        public unsafe static string[] GetEccCurveNames(IntPtr provider)
        {
            int result;
            InteropProperties.BCryptGetProperty(provider, BCRYPT_ECC_CURVE_NAME_LIST, null,0,out result, 0);
            var buffer = stackalloc byte[result];
            InteropProperties.BCryptGetProperty(provider, BCRYPT_ECC_CURVE_NAME_LIST, buffer, result, out result, 0);

            var namesList = Marshal.PtrToStructure<NamesList>((IntPtr)buffer);
            var curveNames = new string[namesList.Number];

            var firstPointer  = Unsafe.Read<IntPtr>((void*)namesList.PointerToArray);

            for(int i = 0; i < namesList.Number;i++)
            {
                firstPointer = Unsafe.Read<IntPtr>((void*)IntPtr.Add(namesList.PointerToArray, IntPtr.Size * i));
                curveNames[i] = Marshal.PtrToStringUni(firstPointer);
            }
            return curveNames;
        }

        private struct NamesList
        {
            public int Number;
            public IntPtr PointerToArray;
        }


        
        
    }
}
