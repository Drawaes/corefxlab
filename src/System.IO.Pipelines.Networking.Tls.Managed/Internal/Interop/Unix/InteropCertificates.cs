using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using static System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Unix.ExceptionHelper;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Unix
{
    internal unsafe static class InteropCertificates
    {
        private const string CryptoDll = "libeay32.dll";
        private const int RSA_PKCS1_PADDING = 1;
        private const int EVP_PKEY_RSA = 6;
        [DllImport(CryptoDll, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private extern static int PKCS12_parse(void* p12, string pass, out IntPtr pkey, out IntPtr cert, byte* certStack);
        [DllImport(CryptoDll, CallingConvention = CallingConvention.Cdecl)]
        private extern static void EVP_PKEY_free(IntPtr key);
        [DllImport(CryptoDll, CallingConvention = CallingConvention.Cdecl)]
        private extern static IntPtr d2i_PKCS12_bio(IntPtr inputBio, IntPtr p12);
        [DllImport(CryptoDll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int EVP_PKEY_type(int type);
        [DllImport(CryptoDll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static int RSA_size(IntPtr rsa);
        [DllImport(CryptoDll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static IntPtr EVP_PKEY_get1_RSA(IntPtr evpKey);
        [DllImport(CryptoDll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static IntPtr EVP_PKEY_CTX_new(IntPtr key, IntPtr engine);
        [DllImport(CryptoDll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static int EVP_PKEY_sign_init(IntPtr ctx);
        [DllImport(CryptoDll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int EVP_PKEY_CTX_set_rsa_padding(IntPtr ctx, int padding);
        [DllImport(CryptoDll, CallingConvention = CallingConvention.Cdecl)]
        public extern static void EVP_PKEY_CTX_free(IntPtr ctx);
        [DllImport(CryptoDll, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_PKEY_CTX_set_signature_md(IntPtr ctx, IntPtr hashType);
        [DllImport(CryptoDll, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_PKEY_sign(IntPtr ctx, IntPtr signatureBuffer, ref int sigBufferLen, IntPtr messageDigest, int messageDigestLength);
        [DllImport(CryptoDll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int EVP_PKEY_CTX_ctrl(IntPtr ctx, int keyType, EVP_PKEY_OP optype, OpTypes cmd, int p1, void* p2);
        [DllImport(CryptoDll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static int EVP_PKEY_decrypt_init(IntPtr ctx);
        [DllImport(CryptoDll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static int EVP_PKEY_decrypt(IntPtr ctx, IntPtr outBuffer, ref int outLen, IntPtr cipherText, int cipherTextLen);

        [Flags]
        internal enum EVP_PKEY_OP : int
        {
            EVP_PKEY_OP_NONE = -1,
            EVP_PKEY_OP_UNDEFINED = 0,
            EVP_PKEY_OP_PARAMGEN = (1 << 1),
            EVP_PKEY_OP_KEYGEN = (1 << 2),
            EVP_PKEY_OP_SIGN = (1 << 3),
            EVP_PKEY_OP_VERIFY = (1 << 4),
            EVP_PKEY_OP_VERIFYRECOVER = (1 << 5),
            EVP_PKEY_OP_SIGNCTX = (1 << 6),
            EVP_PKEY_OP_VERIFYCTX = (1 << 7),
            EVP_PKEY_OP_ENCRYPT = (1 << 8),
            EVP_PKEY_OP_DECRYPT = (1 << 9),
            EVP_PKEY_OP_DERIVE = (1 << 10),
            EVP_PKEY_OP_TYPE_SIG = (EVP_PKEY_OP_SIGN | EVP_PKEY_OP_VERIFY | EVP_PKEY_OP_VERIFYRECOVER | EVP_PKEY_OP_SIGNCTX | EVP_PKEY_OP_VERIFYCTX),
        }
        public static void SetRSAPadding(IntPtr ctx) => CheckCtrlForError(EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP.EVP_PKEY_OP_NONE, OpTypes.EVP_PKEY_CTRL_RSA_PADDING, RSA_PKCS1_PADDING, null));
        public static void SetRSADigest(IntPtr ctx, IntPtr digestPtr) => CheckCtrlForError(EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP.EVP_PKEY_OP_TYPE_SIG, OpTypes.EVP_PKEY_CTRL_MD, 0, (void*)digestPtr));

        private enum KeyType
        {
            RSA = 6,
            DSA = 116,
            DH = 28,
            EC = 408
        }

        private enum OpTypes : int
        {
            EVP_PKEY_ALG_CTRL = 0x1000,
            EVP_PKEY_CTRL_RSA_PADDING = EVP_PKEY_ALG_CTRL + 1,
            EVP_PKEY_CTRL_MD = 1,
        }

        public static int RSAKeySize(IntPtr privateKey)
        {
            var rsaKey = EVP_PKEY_get1_RSA(privateKey);
            return RSA_size(rsaKey);
        }

        public static CertificateType LoadCertificate(byte[] certificateData, out IntPtr privateKeyPointer)
        {
            var memoryBio = InteropBio.BIO_new(InteropBio.BIO_s_mem());
            fixed (byte* certPtr = certificateData)
            {
                InteropBio.BIO_write(memoryBio, certPtr, certificateData.Length);
            }
            var pkc12 = d2i_PKCS12_bio(memoryBio, IntPtr.Zero);
            IntPtr privateKey;
            IntPtr cert;
            CheckOpenSslError(PKCS12_parse(pkc12.ToPointer(), "", out privateKey, out cert, null));
            InteropBio.BIO_free(memoryBio);

            var keyType = GetCertificateTypeFromPrivateKey(privateKey);
            if (keyType == KeyType.RSA)
            {
                privateKeyPointer = privateKey;
                return CertificateType.Rsa;
            }
            else
            {
                privateKeyPointer = IntPtr.Zero;
                return CertificateType.Anonymous;
            }
        }

        private static KeyType GetCertificateTypeFromPrivateKey(IntPtr privateKey)
        {
            var type = Unsafe.Read<int>(privateKey.ToPointer());
            var keyType = (KeyType)EVP_PKEY_type(type);
            return keyType;
        }
    }
}
