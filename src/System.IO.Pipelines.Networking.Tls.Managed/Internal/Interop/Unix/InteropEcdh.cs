using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Unix;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using static global::Interop.Libeay32;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Unix
{
    internal static class InteropEcdh
    {
        private const string Dll = global::Interop.Libraries.OpenSslCrypto;
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static IntPtr EVP_PKEY_CTX_new_id(int id, IntPtr engine);
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static int EVP_PKEY_paramgen_init(IntPtr ctx);
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static int EVP_PKEY_paramgen(IntPtr ctx, out IntPtr ppkey);
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static IntPtr EVP_PKEY_CTX_new(IntPtr pkey, IntPtr engine);
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static int EVP_PKEY_keygen_init(IntPtr ctx);
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static int EVP_PKEY_keygen(IntPtr ctx, out IntPtr ppkey);
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static int EVP_PKEY_size(IntPtr pkey);
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static int EVP_PKEY_bits(IntPtr pKey);
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static IntPtr EVP_PKEY_get1_EC_KEY(IntPtr pkey);
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static IntPtr EC_KEY_get0_public_key(IntPtr key);
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static IntPtr EC_KEY_get0_group(IntPtr key);
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal unsafe extern static IntPtr EC_POINT_point2oct(IntPtr group, IntPtr p, int form, void* buf, IntPtr len, IntPtr ctx);
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal unsafe extern static IntPtr EC_POINT_new(IntPtr group);
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal unsafe extern static int EC_POINT_oct2point(IntPtr group, IntPtr point, void* buf, IntPtr len, IntPtr ctx);
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal unsafe extern static IntPtr EC_KEY_new_by_curve_name(int nid);
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal unsafe extern static int EC_KEY_set_public_key(IntPtr key, IntPtr point);
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal unsafe extern static IntPtr EVP_PKEY_new();
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static int EVP_PKEY_set1_EC_KEY(IntPtr pkey, IntPtr eckey);
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static int EVP_PKEY_derive_init(IntPtr ctx);
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static int EVP_PKEY_derive_set_peer(IntPtr ctx, IntPtr peerKey);
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal unsafe extern static int EVP_PKEY_derive(IntPtr ctx, void* key, ref IntPtr keylen);

        internal unsafe static IntPtr ImportPublicKey(IntPtr ecKey, byte[] keyData, int nid)
        {
            var group = OpenSslPal.CheckPointerError(EC_KEY_get0_group(EVP_PKEY_get1_EC_KEY(ecKey)));
            var newPoint = OpenSslPal.CheckPointerError(EC_POINT_new(group));
            fixed (void* ptr = keyData)
            {
                OpenSslPal.CheckOpenSslError(EC_POINT_oct2point(group, newPoint, ptr, (IntPtr)keyData.Length, IntPtr.Zero));
            }
            //We have a point now we need to make a key
            IntPtr newKey = OpenSslPal.CheckPointerError(EC_KEY_new_by_curve_name(nid));
            OpenSslPal.CheckOpenSslError(EC_KEY_set_public_key(newKey, newPoint));
            IntPtr evpKey = OpenSslPal.CheckPointerError(EVP_PKEY_new());
            OpenSslPal.CheckOpenSslError(EVP_PKEY_set1_EC_KEY(evpKey, newKey));
            return evpKey;
        }

        internal unsafe static void GetPublicKey(IntPtr pKey, Memory<byte> outBuffer)
        {
            var ecKey = OpenSslPal.CheckPointerError(EVP_PKEY_get1_EC_KEY(pKey));
            var pubKey = OpenSslPal.CheckPointerError(EC_KEY_get0_public_key(ecKey));
            var group = OpenSslPal.CheckPointerError(EC_KEY_get0_group(ecKey));
            IntPtr size = EC_POINT_point2oct(group, pubKey, POINT_CONVERSION_UNCOMPRESSED, null, IntPtr.Zero,IntPtr.Zero);
            if(outBuffer.Length != size.ToInt32())
            {
                throw new InvalidOperationException("Size mis-match");
            }
            void* bPtr;
            if(!outBuffer.TryGetPointer(out bPtr))
            {
                throw new InvalidOperationException("No pointer");
            }
            size = EC_POINT_point2oct(group,pubKey, POINT_CONVERSION_UNCOMPRESSED, bPtr, size, IntPtr.Zero);
        }
        
        private const int POINT_CONVERSION_UNCOMPRESSED = 4;
        private const int POINT_CONVERSION_COMPRESSED = 2;

        internal static unsafe int EVP_PKEY_CTX_set_ec_paramgen_curve_nid(IntPtr ctx, int nid)
        {
            var op = EVP_PKEY_Ctrl_OP.EVP_PKEY_OP_PARAMGEN | EVP_PKEY_Ctrl_OP.EVP_PKEY_OP_KEYGEN;
            return OpenSslPal.CheckCtrlForError(EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC,op, EVP_PKEY_Ctrl_Command.EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID, nid, null));
        }

        internal static IntPtr NewEcdhePKey(int curveNid)
        {
            IntPtr ctx = OpenSslPal.CheckPointerError(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, IntPtr.Zero));
            OpenSslPal.CheckOpenSslError(EVP_PKEY_paramgen_init(ctx));
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curveNid);
            IntPtr paramsPtr;
            OpenSslPal.CheckOpenSslError(EVP_PKEY_paramgen(ctx,out paramsPtr));
            //Context for key gen
            IntPtr keyCtx = OpenSslPal.CheckPointerError(EVP_PKEY_CTX_new(paramsPtr, IntPtr.Zero));
            OpenSslPal.CheckOpenSslError(EVP_PKEY_keygen_init(keyCtx));
            IntPtr keyPtr;
            OpenSslPal.CheckOpenSslError(EVP_PKEY_keygen(keyCtx, out keyPtr));
            return keyPtr;
        }

        internal const int EVP_PKEY_EC = 408;
                
    }
}
