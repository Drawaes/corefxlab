using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Unix;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
using static global::Interop;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Unix
{
    internal partial class OpenSslPal
    {
        private static readonly IOpenSslHelper _helper;

        static unsafe OpenSslPal()
        {
            _helper = new OpenSsl1Pal();
            //try
            //{
            //    var result = LibCrypto.OPENSSL_init_crypto(0, null);
            //    if (result == 1)
            //    {
            //        //We have openssl 1.1
            //        _helper = new OpenSsl11Helper();
            //    }
            //    else
            //    {
            //        _helper = new OpenSsl1Pal();
            //    }
            //}
            //catch
            //{
            //    _helper = new OpenSsl1Pal();
            //}
        }

        public static void Init()
        { }
        public static void CheckOpenSslError(int returnCode) => _helper.CheckOpenSslError(returnCode);
        public static int CheckCtrlForError(int returnCode) => _helper.CheckCtrlForError(returnCode);
        public static IntPtr CheckPointerError(IntPtr pointer) => _helper.CheckPointerError(pointer);
        public static SafeEvpMdCtxHandle CreateHash(IntPtr hashProvider) => _helper.CreateHash(hashProvider);
        public static SafeEvpMdCtxHandle CopyHash(SafeEvpMdCtxHandle original) => _helper.CopyHash(original);
        public static int[] GetCurveNids() => _helper.GetCurveNids();
    }
}
