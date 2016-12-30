using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.TlsSpec;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using static global::Interop.Libeay32;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Unix
{
    internal partial class OpenSslPal
    {
        private partial class OpenSsl1Pal : IOpenSslHelper
        {
            public unsafe int[] GetCurveNids()
            {
                var returnValues = new int[((ushort[])Enum.GetValues(typeof(EllipticCurves))).Max() + 1];

                IntPtr result = EC_get_builtin_curves(null, IntPtr.Zero);
                var numberOfItems = result.ToInt32();

                var curves = stackalloc EC_builtin_curve[numberOfItems];
                result = EC_get_builtin_curves(curves, result);
                numberOfItems = result.ToInt32();
                for (var i = 0; i < numberOfItems; i++)
                {
                    var name = Marshal.PtrToStringAnsi(OBJ_nid2ln(curves[i].nid));
                    EllipticCurves curve;
                    if (Enum.TryParse(name, true, out curve))
                    {
                        returnValues[(int)curve] = curves[i].nid;
                    }
                }
                return returnValues;
            }
        }
    }
}
