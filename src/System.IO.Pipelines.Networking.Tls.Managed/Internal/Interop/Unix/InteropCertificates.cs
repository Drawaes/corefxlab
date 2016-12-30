using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Unix;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using static global::Interop.Libeay32;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Unix
{
    internal unsafe static class InteropCertificates
    {
        private const string CryptoDll = global::Interop.Libraries.OpenSslCrypto;
        private const int RSA_PKCS1_PADDING = 1;
        private const int EVP_PKEY_RSA = 6;

        [DllImport(CryptoDll, CallingConvention = CallingConvention.Cdecl)]
        private extern static IntPtr d2i_PKCS12_bio(IntPtr inputBio, IntPtr p12);
        [DllImport(CryptoDll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static IntPtr EVP_PKEY_get1_RSA(IntPtr evpKey);
        [DllImport(CryptoDll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static int EVP_PKEY_sign_init(IntPtr ctx);
        [DllImport(CryptoDll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int EVP_PKEY_CTX_set_rsa_padding(IntPtr ctx, int padding);
        [DllImport(CryptoDll, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_PKEY_CTX_set_signature_md(IntPtr ctx, IntPtr hashType);
        [DllImport(CryptoDll, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_PKEY_sign(IntPtr ctx, IntPtr signatureBuffer, ref int sigBufferLen, IntPtr messageDigest, int messageDigestLength);
        [DllImport(CryptoDll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static int EVP_PKEY_decrypt(IntPtr ctx, IntPtr outBuffer, ref int outLen, IntPtr cipherText, int cipherTextLen);
                
        public static void SetRSAPadding(IntPtr ctx) => OpenSslPal.CheckCtrlForError(EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_Ctrl_OP.EVP_PKEY_OP_NONE, EVP_PKEY_Ctrl_Command.EVP_PKEY_CTRL_RSA_PADDING, RSA_PKCS1_PADDING, null));
        public static void SetRSADigest(IntPtr ctx, IntPtr digestPtr) => OpenSslPal.CheckCtrlForError(EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_Ctrl_OP.EVP_PKEY_OP_TYPE_SIG, EVP_PKEY_Ctrl_Command.EVP_PKEY_CTRL_MD, 0, (void*)digestPtr));

        private enum KeyType
        {
            RSA = 6,
            DSA = 116,
            DH = 28,
            EC = 408
        }
        
        public static int RSAKeySize(IntPtr privateKey)
        {
            var rsaKey = EVP_PKEY_get1_RSA(privateKey);
            return RSA_size(rsaKey);
        }

        public static CertificateType LoadCertificate(byte[] certificateData, out IntPtr privateKeyPointer)
        {
            var memoryBio = BIO_new(BIO_s_mem_type);
            fixed (byte* certPtr = certificateData)
            {
                BIO_write(memoryBio, certPtr, certificateData.Length);
            }
            var pkc12 = d2i_PKCS12_bio(memoryBio, IntPtr.Zero);
            IntPtr privateKey;
            IntPtr cert;
            OpenSslPal.CheckOpenSslError(PKCS12_parse(pkc12.ToPointer(), "", out privateKey, out cert, null));
            BIO_free(memoryBio);

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
