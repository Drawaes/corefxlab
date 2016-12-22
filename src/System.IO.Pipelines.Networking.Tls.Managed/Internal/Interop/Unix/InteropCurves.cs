using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.TlsSpec;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Unix
{
    internal static class InteropCurves
    {
        private const string Dll = "libeay32.dll";

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern unsafe IntPtr EC_get_builtin_curves(EC_builtin_curve* r, IntPtr nitems);
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern unsafe IntPtr OBJ_nid2ln(int n);


        [StructLayout(LayoutKind.Sequential)]
        private unsafe struct EC_builtin_curve
        {
            internal int nid;
            internal void* comment;
        }

        internal static unsafe int[] GetCurveNids()
        {
            var returnValues = new int[((int[])Enum.GetValues(typeof(EllipticCurves))).Max() + 1];

            IntPtr result = EC_get_builtin_curves(null, IntPtr.Zero);
            var numberOfItems = result.ToInt32();

            var curves = stackalloc EC_builtin_curve[numberOfItems];
            result = EC_get_builtin_curves(curves, result);
            numberOfItems = result.ToInt32();
            for(var i = 0; i < numberOfItems;i++)
            {
                var name = Marshal.PtrToStringAnsi(OBJ_nid2ln(curves[i].nid));
                EllipticCurves curve;
                if(Enum.TryParse(name, true, out curve))
                {
                    returnValues[(int)curve] = curves[i].nid;
                }
            }
            return returnValues;
        }
    }
}
