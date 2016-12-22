using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Windows;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.TlsSpec;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
using static global::Interop.BCrypt;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Windows
{
    internal static class BCryptSecretsHelper
    {
        internal static SafeBCryptKeyHandle GenerateKeyPair(SafeBCryptAlgorithmHandle provider)
        {
            SafeBCryptKeyHandle returnValue;
            ExceptionHelper.CheckReturnCode(BCryptGenerateKeyPair(provider, out returnValue, 0, 0));
            ExceptionHelper.CheckReturnCode(BCryptFinalizeKeyPair(returnValue, 0));
            return returnValue;
        }

        internal static int GetPublicKeyExportSize(SafeBCryptKeyHandle key)
        {
            int keySize;
            ExceptionHelper.CheckReturnCode(
                BCryptExportKey(key, IntPtr.Zero, KeyBlobType.BCRYPT_ECCPUBLIC_BLOB, IntPtr.Zero, 0, out keySize, 0));
            //8 byte header ontop that isn't sent
            return keySize - 8;
        }

        internal static unsafe SafeBCryptKeyHandle ImportPublicKey(SafeBCryptAlgorithmHandle provider, ReadableBuffer buffer, int keyLength)
        {
            //Now we have the point and can load the key
            var keyBuffer = stackalloc byte[keyLength + 8];
            var blobHeader = new BCRYPT_ECCKEY_BLOB();
            blobHeader.Magic = KeyBlobMagicNumber.BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC;
            blobHeader.cbKey = keyLength / 2;
            Marshal.StructureToPtr(blobHeader, (IntPtr)keyBuffer, false);
            buffer.CopyTo(new Span<byte>(keyBuffer + 8, keyLength));
            SafeBCryptKeyHandle keyHandle;
            ExceptionHelper.CheckReturnCode(BCryptImportKeyPair(provider, null, KeyBlobType.BCRYPT_ECCPUBLIC_BLOB, out keyHandle, (IntPtr)keyBuffer, keyLength + 8, 0));
            return keyHandle;
        }

        internal static SafeBCryptSecretHandle CreateSecret(SafeBCryptKeyHandle publicKey, SafeBCryptKeyHandle privateKey)
        {
            SafeBCryptSecretHandle returnPtr;
            ExceptionHelper.CheckReturnCode(BCryptSecretAgreement(privateKey, publicKey, out returnPtr, 0));
            return returnPtr;
        }

        internal unsafe static void ExportPublicKey(SafeBCryptKeyHandle keyPair, Memory<byte> output)
        {
            var tmpBuffer = stackalloc byte[output.Length + 8];
            int resultSize;
            ExceptionHelper.CheckReturnCode(BCryptExportKey(keyPair, IntPtr.Zero, KeyBlobType.BCRYPT_ECCPUBLIC_BLOB, (IntPtr)tmpBuffer, output.Length + 8, out resultSize, 0));
            var keySpan = new Span<byte>(tmpBuffer + 8, output.Length);
            keySpan.CopyTo(output.Span);
        }

        internal unsafe static byte[] GenerateMasterSecret12(SafeBCryptSecretHandle secret, IHashProvider hashProvider, Span<byte> clientRandom, Span<byte> serverRandom)
        {
            var seed = stackalloc byte[clientRandom.Length + serverRandom.Length];
            var tmpSpan = new Span<byte>(seed, clientRandom.Length + serverRandom.Length);
            clientRandom.CopyTo(tmpSpan);
            serverRandom.CopyTo(tmpSpan.Slice(clientRandom.Length));
            uint* version = stackalloc uint[1];
            version[0] = 0x0303;
            var buffDescription = new BCryptBufferDesc();
            var bufferArray = stackalloc BCryptBuffer[4];
            bufferArray[0] = new BCryptBuffer() { BufferType = NCryptBufferDescriptors.KDF_HASH_ALGORITHM, cbBuffer = hashProvider.AlgIdLength, pvBuffer = hashProvider.AlgId };
            bufferArray[1] = new BCryptBuffer() { BufferType = NCryptBufferDescriptors.KDF_TLS_PRF_LABEL, cbBuffer = Tls12Utils.MasterSecretSize, pvBuffer = Tls12Utils.MasterSecretPointer };
            bufferArray[2] = new BCryptBuffer() { BufferType = NCryptBufferDescriptors.KDF_TLS_PRF_SEED, cbBuffer = tmpSpan.Length, pvBuffer = (IntPtr)seed };
            bufferArray[3] = new BCryptBuffer() { BufferType = NCryptBufferDescriptors.KDF_TLS_PRF_PROTOCOL, cbBuffer = 4, pvBuffer = (IntPtr)version };
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
