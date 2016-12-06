using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Internal.ManagedTls;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.BulkCiphers
{
    public class BulkCipherKey : IDisposable
    {
        private OwnedMemory<byte> _buffer;
        private IntPtr _keyHandle;
        private int _tagLength;

        public unsafe BulkCipherKey(IntPtr providerHandle, OwnedMemory<byte> buffer, byte[] key)
        {
            try
            {
                _buffer = buffer;
                IntPtr handle;
                void* memPtr;
                if (!buffer.Memory.TryGetPointer(out memPtr))
                {
                    throw new NotImplementedException();
                }
                byte[] keyBlob = new byte[Marshal.SizeOf(typeof(InteropStructs.BCRYPT_KEY_DATA_BLOB)) + key.Length];
                unsafe
                {
                    fixed (byte* pbKeyBlob = keyBlob)
                    {
                        InteropStructs.BCRYPT_KEY_DATA_BLOB* pkeyDataBlob = (InteropStructs.BCRYPT_KEY_DATA_BLOB*)pbKeyBlob;
                        pkeyDataBlob->dwMagic = InteropStructs.KeyBlobMagicNumber.KeyDataBlob;
                        pkeyDataBlob->dwVersion = 1;
                        pkeyDataBlob->cbKeyData = key.Length;
                    }
                }
                Buffer.BlockCopy(key, 0, keyBlob, Marshal.SizeOf(typeof(InteropStructs.BCRYPT_KEY_DATA_BLOB)), key.Length);
                Interop.CheckReturnOrThrow(Interop.BCryptImportKey(providerHandle, IntPtr.Zero, "KeyDataBlob"
                    , out handle, (IntPtr)memPtr, buffer.Length
                    , keyBlob, keyBlob.Length, 0));
                _keyHandle = handle;
            }
            catch
            {
                Dispose();
                throw;
            }
        }

        public unsafe byte[] Encrypt(byte[] nounce, byte[] plainText, byte[] additionalData,out byte[] authTagResult)
        {
            var ivLength = InteropProperties.GetBlockLength(_keyHandle);
            var iv = stackalloc byte[ivLength];
            var cInfo = new InteropStructs.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
            cInfo.dwInfoVersion = 1;
            cInfo.cbSize = Marshal.SizeOf(typeof(InteropStructs.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));

            var tag = new byte[16];
            var cipherText = new byte[plainText.Length];
            var block = stackalloc byte[16];
            fixed(void* nPtr = nounce)
            fixed(void* pPtr = plainText)
            fixed(void* aPtr = additionalData)
            fixed(void* tPtr = tag)
            fixed(void* cPtr = cipherText)
            {
                cInfo.cbAuthData = additionalData.Length;
                cInfo.cbNonce = nounce.Length;
                cInfo.cbTag = tag.Length;
                //cInfo.pbMacContext = (IntPtr)aPtr;
                //cInfo.cbMacContext = additionalData.Length;
                cInfo.dwFlags = InteropStructs.AuthenticatedCipherModeInfoFlags.None;
                cInfo.pbAuthData =(IntPtr) aPtr;
                cInfo.pbNonce = (IntPtr) nPtr;
                cInfo.pbTag = (IntPtr)tPtr;

                int amountWritten = 0;
                var result = Interop.BCryptEncrypt(_keyHandle, pPtr, plainText.Length, &cInfo, null,0, cPtr, cipherText.Length, out amountWritten, 0);
            }
            authTagResult = tag;
            return cipherText;

        }

        public unsafe byte[] Decrypt(byte[] nounce, byte[] cipherText, byte[] tag, byte[] additionalData)
        {
            int blockLength = InteropProperties.GetBlockLength(_keyHandle);
            var returnValue = new byte[cipherText.Length];
            //var iv = new byte[blockLength];
            //Buffer.BlockCopy(nounce, 0,iv,0,nounce.Length);

            fixed (void* nPtr = nounce)
            fixed (void* tPtr = tag)
            fixed (void* aPtr = additionalData)
            {
                var cInfo = new InteropStructs.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
                cInfo.cbNonce = nounce.Length;
                cInfo.pbNonce = (IntPtr)nPtr;
                cInfo.dwInfoVersion = 1;
                cInfo.cbSize = Marshal.SizeOf(typeof(InteropStructs.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));
                cInfo.pbTag = (IntPtr)tPtr;
                cInfo.cbTag = tag.Length;
                cInfo.cbAuthData = additionalData.Length; 
                cInfo.pbAuthData = (IntPtr)aPtr;
                
                cInfo.dwFlags = InteropStructs.AuthenticatedCipherModeInfoFlags.None;
                int resultSize;
                Interop.CheckReturnOrThrow(
                Interop.BCryptDecrypt(_keyHandle, cipherText, cipherText.Length, ref cInfo,nounce,nounce.Length, returnValue
                , cipherText.Length, out resultSize, 0));
            }
            return returnValue;
        }

        public void Dispose()
        {
            throw new NotImplementedException();
        }
    }
}
