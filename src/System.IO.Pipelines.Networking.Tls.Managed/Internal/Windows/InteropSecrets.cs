using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using static System.IO.Pipelines.Networking.Tls.Managed.Internal.Windows.InteropStructs;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Windows
{
    public static class InteropSecrets
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

        public static IntPtr GenerateKeyPair(IntPtr provider)
        {
            IntPtr returnValue;
            ExceptionHelper.CheckReturnCode(BCryptGenerateKeyPair(provider, out returnValue, 0, 0));
            ExceptionHelper.CheckReturnCode(BCryptFinalizeKeyPair(returnValue,0));
            return returnValue;
        }

        public static IntPtr CreateSecret(IntPtr publicKey, IntPtr privateKey)
        {
            IntPtr returnPtr;
            ExceptionHelper.CheckReturnCode(BCryptSecretAgreement(privateKey, publicKey, out returnPtr, 0));
            return returnPtr;
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
            ExceptionHelper.CheckReturnCode(BCryptExportKey(keyPair, IntPtr.Zero, BCRYPT_ECCPUBLIC_BLOB, (IntPtr)tmpBuffer, output.Length + 8 ,out resultSize, 0));
            var keySpan = new Span<byte>(tmpBuffer + 8, output.Length);
            keySpan.CopyTo(output.Span);
        }

        public unsafe static void GenerateMasterSecret12(IntPtr secret, HashProvider hashProvider, byte[] clientRandom, byte[] serverRandom)
        {
            fixed (void* clientPtr = clientRandom)
            fixed (void* serverPtr = serverRandom)
            {
                uint version = 0x0303;
                var buffDescription = new BCryptBufferDesc();
                var bufferArray = stackalloc BCryptBuffer[5];
                bufferArray[0] = new BCryptBuffer() { BufferType = BufferTypes.KDF_HASH_ALGORITHM, cbBuffer = hashProvider.AlgIdLength, pvBuffer = (void*) hashProvider.AlgId  };
                bufferArray[1] = new BCryptBuffer() { BufferType = BufferTypes.KDF_TLS_PRF_LABEL, cbBuffer = TlsLabels.MasterSecretSize, pvBuffer = (void*) TlsLabels.MasterSecretPointer };
                bufferArray[2] = new BCryptBuffer() { BufferType = BufferTypes.KDF_TLS_PRF_SEED, cbBuffer = clientRandom.Length, pvBuffer = clientPtr };
                bufferArray[3] = new BCryptBuffer() { BufferType = BufferTypes.KDF_TLS_PRF_SEED, cbBuffer = serverRandom.Length, pvBuffer = serverPtr };
                bufferArray[4] = new BCryptBuffer() { BufferType = BufferTypes.KDF_TLS_PRF_PROTOCOL, cbBuffer = 4, pvBuffer = &version };
                buffDescription.cBuffers = 5;
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
                System.IO.File.WriteAllText("C:\\Code\\KeyLog\\Master.log", BitConverter.ToString(masterSecret));
            }
        }
    }
}
