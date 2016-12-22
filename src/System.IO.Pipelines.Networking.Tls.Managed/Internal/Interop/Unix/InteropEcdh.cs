using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Unix
{
    internal static class InteropEcdh
    {
        private const string Dll = "libeay32.dll";
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static IntPtr EVP_PKEY_CTX_new_id(int id, IntPtr engine);
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static int EVP_PKEY_paramgen_init(IntPtr ctx);
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal unsafe extern static int EVP_PKEY_CTX_ctrl(IntPtr ctx, int keyType,InteropCertificates.EVP_PKEY_OP op, EVP_PKEY_CTRL cmd, int param, void* ptr);
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

        internal unsafe static void GetPublicKey(IntPtr pKey, Memory<byte> outBuffer)
        {
            var ecKey = ExceptionHelper.CheckPointerError(EVP_PKEY_get1_EC_KEY(pKey));
            var pubKey = ExceptionHelper.CheckPointerError(EC_KEY_get0_public_key(ecKey));
            var group = ExceptionHelper.CheckPointerError(EC_KEY_get0_group(ecKey));
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
            var op = InteropCertificates.EVP_PKEY_OP.EVP_PKEY_OP_PARAMGEN | InteropCertificates.EVP_PKEY_OP.EVP_PKEY_OP_KEYGEN;
            return ExceptionHelper.CheckCtrlForError(EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC,op,  EVP_PKEY_CTRL.EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID, nid, null));
        }

        internal static IntPtr NewEcdhePKey(int curveNid)
        {
            IntPtr ctx = ExceptionHelper.CheckPointerError(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, IntPtr.Zero));
            ExceptionHelper.CheckOpenSslError(EVP_PKEY_paramgen_init(ctx));
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curveNid);
            IntPtr paramsPtr;
            ExceptionHelper.CheckOpenSslError(EVP_PKEY_paramgen(ctx,out paramsPtr));
            //Context for key gen
            IntPtr keyCtx = ExceptionHelper.CheckPointerError(EVP_PKEY_CTX_new(paramsPtr, IntPtr.Zero));
            ExceptionHelper.CheckOpenSslError(EVP_PKEY_keygen_init(keyCtx));
            IntPtr keyPtr;
            ExceptionHelper.CheckOpenSslError(EVP_PKEY_keygen(keyCtx, out keyPtr));
            return keyPtr;
        }

        internal const int EVP_PKEY_EC = 408;
        
        [Flags]
        internal enum EVP_PKEY_CTRL:int
        {
            EVP_PKEY_ALG_CTRL = 0x1000,
            EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID             =(EVP_PKEY_ALG_CTRL + 1),
            EVP_PKEY_CTRL_EC_PARAM_ENC                      =(EVP_PKEY_ALG_CTRL + 2),
            EVP_PKEY_CTRL_EC_ECDH_COFACTOR                  =(EVP_PKEY_ALG_CTRL + 3),
            EVP_PKEY_CTRL_EC_KDF_TYPE                       =(EVP_PKEY_ALG_CTRL + 4),
            EVP_PKEY_CTRL_EC_KDF_MD                         =(EVP_PKEY_ALG_CTRL + 5),
            EVP_PKEY_CTRL_GET_EC_KDF_MD                     =(EVP_PKEY_ALG_CTRL + 6),
            EVP_PKEY_CTRL_EC_KDF_OUTLEN                     =(EVP_PKEY_ALG_CTRL + 7),
            EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN                 =(EVP_PKEY_ALG_CTRL + 8),
            EVP_PKEY_CTRL_EC_KDF_UKM                        =(EVP_PKEY_ALG_CTRL + 9),
            EVP_PKEY_CTRL_GET_EC_KDF_UKM                    =(EVP_PKEY_ALG_CTRL + 10),
        }
    }
}
