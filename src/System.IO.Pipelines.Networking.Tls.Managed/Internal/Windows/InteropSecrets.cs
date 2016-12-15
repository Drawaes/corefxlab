using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using static System.IO.Pipelines.Networking.Tls.Managed.Internal.Windows.InteropStructs;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Windows
{
    public unsafe static class InteropSecrets
    {
        private const string Dll = "Bcrypt.dll";
        private const string BCRYPT_ECCPUBLIC_BLOB = "ECCPUBLICBLOB";
        private const string BCRYPT_KDF_TLS_PRF = "TLS_PRF";

        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern ReturnCodes BCryptGenerateKeyPair(IntPtr hAlgorithm, out IntPtr phKey, int dwLength, int dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern ReturnCodes BCryptFinalizeKeyPair(IntPtr hKey, uint dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern ReturnCodes BCryptExportKey(IntPtr hKey, IntPtr encyrptKey, string blobType, IntPtr pbOutput, int cbOutput, out int pcbResult, uint dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern ReturnCodes BCryptImportKeyPair(IntPtr hAlgorithm, IntPtr hImportKey, string pszBlobType, out IntPtr phKey, IntPtr pbInput, int cbInput, uint dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern ReturnCodes BCryptSecretAgreement(IntPtr hPrivKey, IntPtr hPubKey, out IntPtr phSecret, uint dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern ReturnCodes BCryptDeriveKey(IntPtr hSharedSecret, string pwszKDF, void* pParameterList, IntPtr pbDerivedKey, int cbDerivedKey, out int pcbResult, uint dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern ReturnCodes BCryptDestroySecret(IntPtr hSecret);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern ReturnCodes BCryptDestroyKey(IntPtr hKey);

        public static void DestroyPublicKey(IntPtr key)
        {
            ExceptionHelper.CheckReturnCode(BCryptDestroyKey(key));
        }

        public static IntPtr GenerateKeyPair(IntPtr provider)
        {
            IntPtr returnValue;
            ExceptionHelper.CheckReturnCode(BCryptGenerateKeyPair(provider, out returnValue, 0, 0));
            ExceptionHelper.CheckReturnCode(BCryptFinalizeKeyPair(returnValue, 0));
            return returnValue;
        }

        public static IntPtr CreateSecret(IntPtr publicKey, IntPtr privateKey)
        {
            IntPtr returnPtr;
            ExceptionHelper.CheckReturnCode(BCryptSecretAgreement(privateKey, publicKey, out returnPtr, 0));
            return returnPtr;
        }

        public static void DestroySecret(IntPtr ptr)
        {
            ExceptionHelper.CheckReturnCode(BCryptDestroySecret(ptr));
        }

        public static unsafe IntPtr ImportPublicKey(IntPtr provider, ReadableBuffer buffer, int keyLength)
        {
            //Now we have the point and can load the key
            var keyBuffer = stackalloc byte[keyLength + 8];
            var blobHeader = new InteropStructs.BCRYPT_ECCKEY_BLOB();
            blobHeader.dwMagic = InteropStructs.KeyBlobMagicNumber.EchdPublic;
            blobHeader.cbKey = keyLength / 2;
            Marshal.StructureToPtr(blobHeader, (IntPtr)keyBuffer, false);
            buffer.CopyTo(new Span<byte>(keyBuffer + 8, keyLength));

            IntPtr keyHandle;
            ExceptionHelper.CheckReturnCode(BCryptImportKeyPair(provider, IntPtr.Zero, BCRYPT_ECCPUBLIC_BLOB, out keyHandle, (IntPtr)keyBuffer, keyLength + 8, 0));
            return keyHandle;
        }

        public static int GetPublicKeyExportSize(IntPtr key)
        {
            int keySize;
            ExceptionHelper.CheckReturnCode(
                BCryptExportKey(key, IntPtr.Zero, BCRYPT_ECCPUBLIC_BLOB, IntPtr.Zero, 0, out keySize, 0));
            //8 byte header ontop that isn't sent
            return keySize - 8;
        }

        public unsafe static void ExportPublicKey(IntPtr keyPair, Memory<byte> output)
        {
            var tmpBuffer = stackalloc byte[output.Length + 8];
            int resultSize;
            ExceptionHelper.CheckReturnCode(BCryptExportKey(keyPair, IntPtr.Zero, BCRYPT_ECCPUBLIC_BLOB, (IntPtr)tmpBuffer, output.Length + 8, out resultSize, 0));
            var keySpan = new Span<byte>(tmpBuffer + 8, output.Length);
            keySpan.CopyTo(output.Span);
        }

        public unsafe static byte[] GenerateMasterSecret12(IntPtr secret, HashProvider hashProvider, Span<byte> clientRandom, Span<byte> serverRandom)
        {
            var seed = stackalloc byte[clientRandom.Length + serverRandom.Length];
            var tmpSpan = new Span<byte>(seed, clientRandom.Length + serverRandom.Length);
            clientRandom.CopyTo(tmpSpan);
            serverRandom.CopyTo(tmpSpan.Slice(clientRandom.Length));
            uint version = 0x0303;
            var buffDescription = new BCryptBufferDesc();
            var bufferArray = stackalloc BCryptBuffer[4];
            bufferArray[0] = new BCryptBuffer() { BufferType = BufferTypes.KDF_HASH_ALGORITHM, cbBuffer = hashProvider.AlgIdLength, pvBuffer = (void*)hashProvider.AlgId };
            bufferArray[1] = new BCryptBuffer() { BufferType = BufferTypes.KDF_TLS_PRF_LABEL, cbBuffer = TlsLabels.MasterSecretSize, pvBuffer = (void*)TlsLabels.MasterSecretPointer };
            bufferArray[2] = new BCryptBuffer() { BufferType = BufferTypes.KDF_TLS_PRF_SEED, cbBuffer = tmpSpan.Length, pvBuffer = seed };
            bufferArray[3] = new BCryptBuffer() { BufferType = BufferTypes.KDF_TLS_PRF_PROTOCOL, cbBuffer = 4, pvBuffer = &version };
            buffDescription.cBuffers = 4;
            buffDescription.pBuffers = (IntPtr)bufferArray;
            int sizeOfResult;
            ExceptionHelper.CheckReturnCode(
                BCryptDeriveKey(secret, BCRYPT_KDF_TLS_PRF, &buffDescription, IntPtr.Zero, 0, out sizeOfResult, 0));

            var masterSecret = new byte[sizeOfResult];
            fixed (void* msPtr = masterSecret)
            {
                ExceptionHelper.CheckReturnCode(
                    BCryptDeriveKey(secret, BCRYPT_KDF_TLS_PRF, &buffDescription, (IntPtr)msPtr, sizeOfResult, out sizeOfResult, 0));
            }
            return masterSecret;
        }
    }
}
