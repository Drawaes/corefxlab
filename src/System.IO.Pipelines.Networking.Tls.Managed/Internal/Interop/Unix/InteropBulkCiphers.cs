using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Unix
{
    internal unsafe static class InteropBulkCiphers
    {
        private const string Dll = global::Interop.Libraries.OpenSslCrypto;
        
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static int EVP_CIPHER_key_length(IntPtr cipher);
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static SafeEvpCipherCtxHandle EVP_CIPHER_CTX_new();
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static int EVP_CIPHER_CTX_ctrl(SafeEvpCipherCtxHandle ctx, EVP_CIPHER_CTRL type, int arg, void* ptr);
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static void EVP_CIPHER_CTX_free(IntPtr ctx);
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static int EVP_EncryptInit_ex(SafeEvpCipherCtxHandle ctx, IntPtr cipher, IntPtr engine, byte* key, byte* iv);
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static int EVP_DecryptUpdate(SafeEvpCipherCtxHandle ctx, void* outBuffer, ref int outLength, void* inBuffer, int inLength);
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static int EVP_EncryptUpdate(SafeEvpCipherCtxHandle ctx, void* outBuffer, ref int outLength, void* inBuffer, int inLength);
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static int EVP_DecryptFinal_ex(SafeEvpCipherCtxHandle ctx, void* outm, ref int outlen);
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static int EVP_EncryptFinal_ex(SafeEvpCipherCtxHandle ctx, void* outm, ref int outlen);

        public enum EVP_CIPHER_CTRL : int
        {
            EVP_CTRL_INIT = 0x0,
            EVP_CTRL_SET_KEY_LENGTH = 0x1,
            EVP_CTRL_GET_RC2_KEY_BITS = 0x2,
            EVP_CTRL_SET_RC2_KEY_BITS = 0x3,
            EVP_CTRL_GET_RC5_ROUNDS = 0x4,
            EVP_CTRL_SET_RC5_ROUNDS = 0x5,
            EVP_CTRL_RAND_KEY = 0x6,
            EVP_CTRL_PBE_PRF_NID = 0x7,
            EVP_CTRL_COPY = 0x8,
            EVP_CTRL_GCM_SET_IVLEN = 0x9,
            EVP_CTRL_GCM_GET_TAG = 0x10,
            EVP_CTRL_GCM_SET_TAG = 0x11,
            EVP_CTRL_GCM_SET_IV_FIXED = 0x12,
            EVP_CTRL_GCM_IV_GEN = 0x13,
            EVP_CTRL_CCM_SET_IVLEN = EVP_CTRL_GCM_SET_IVLEN,
            EVP_CTRL_CCM_GET_TAG = EVP_CTRL_GCM_GET_TAG,
            EVP_CTRL_CCM_SET_TAG = EVP_CTRL_GCM_SET_TAG,
            EVP_CTRL_CCM_SET_L = 0x14,
            EVP_CTRL_CCM_SET_MSGLEN = 0x15,
        }
    }
}
