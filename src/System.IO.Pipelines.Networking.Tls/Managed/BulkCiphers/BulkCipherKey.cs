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
        private int _maxTagLength;
        private int _blockLength;
        
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
                var tagLength = InteropProperties.GetAuthTagLengths(providerHandle);
                _maxTagLength = tagLength.dwMaxLength;
                _blockLength = InteropProperties.GetBlockLength(_keyHandle);
            }
            catch
            {
                Dispose();
                throw;
            }
        }

        internal unsafe void EncryptFrame(ReadableBuffer decryptedData, ref WritableBuffer encryptedData, TlsFrameType frameType, ulong sequenceNumber, byte[] nounce)
        {
            var length = decryptedData.Length;
            var additionalData = stackalloc byte[13];
            var spanAdditional = new Span<byte>(additionalData, 13);
            spanAdditional.Write64BitNumber(sequenceNumber);
            spanAdditional = spanAdditional.Slice(8);
            spanAdditional.Write((byte) frameType);
            spanAdditional.Slice(1).Write((ushort) 0x0303);
            spanAdditional.Slice(3).Write16BitNumber((ushort)length);

            encryptedData.Ensure(11);
            encryptedData.WriteBigEndian(frameType);
            encryptedData.WriteBigEndian<ushort>(0x0303);
            encryptedData.WriteBigEndian((ushort)(length + 8 + 16));
            encryptedData.WriteBigEndian(sequenceNumber);

            var nounceSpan = new Span<byte>(nounce);
            nounceSpan.Slice(4).Write64BitNumber(sequenceNumber);
            var tag = stackalloc byte[16];
            var cInfo = new InteropStructs.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
            cInfo.dwInfoVersion = 1;
            cInfo.cbSize = Marshal.SizeOf(typeof(InteropStructs.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));
            cInfo.cbAuthData = 13;
            cInfo.pbAuthData = (IntPtr)additionalData;
            cInfo.pbTag = (IntPtr)tag;
            cInfo.cbTag = 16;

            if (decryptedData.IsSingleSpan)
            {
                
                encryptedData.Ensure(decryptedData.Length);
                void* outPointer;
                encryptedData.Memory.TryGetPointer(out outPointer);
                void* inPointer;
                decryptedData.First.TryGetPointer(out inPointer);
                fixed(void* nPtr = nounce)
                {
                    cInfo.cbNonce = nounce.Length;
                    cInfo.dwFlags = InteropStructs.AuthenticatedCipherModeInfoFlags.None;
                    cInfo.pbNonce = (IntPtr)nPtr;

                    int amountWritten = 0;
                    Interop.CheckReturnOrThrow(
                    Interop.BCryptEncrypt(_keyHandle, inPointer, decryptedData.Length, &cInfo, null, 0, outPointer, decryptedData.Length, out amountWritten, 0));
                }
                encryptedData.Advance(decryptedData.Length);
                encryptedData.Write(new Span<byte>(tag,16));
            }
            else
            {
                var iv = stackalloc byte[_blockLength];
                var macRecord = stackalloc byte[_maxTagLength];
                cInfo.dwFlags = InteropStructs.AuthenticatedCipherModeInfoFlags.ChainCalls;
                cInfo.cbMacContext = _maxTagLength;
                cInfo.pbMacContext = (IntPtr) macRecord;
                fixed(void* nPtr = nounce)
                {
                    cInfo.cbNonce = nounce.Length;
                    cInfo.pbNonce = (IntPtr) nPtr;
                    int totalLength = decryptedData.Length;
                    foreach(var b in decryptedData)
                    {
                        if (b.Length > 0)
                        {
                            totalLength = totalLength - b.Length;
                            if(totalLength == 0)
                            {
                                cInfo.dwFlags = InteropStructs.AuthenticatedCipherModeInfoFlags.None;
                            }
                            void* outPointer;
                            encryptedData.Ensure(b.Span.Length);
                            encryptedData.Memory.TryGetPointer(out outPointer);
                            void* inPointer;
                            b.TryGetPointer(out inPointer);

                            int amountWritten = 0;
                            if(cInfo.dwFlags != InteropStructs.AuthenticatedCipherModeInfoFlags.None)
                            {
                                Console.WriteLine("Test");
                            }
                            var result = Interop.BCryptEncrypt(_keyHandle, inPointer, b.Length, &cInfo, iv, (uint)_blockLength, outPointer, b.Length, out amountWritten, 0);
                            cInfo.dwFlags = InteropStructs.AuthenticatedCipherModeInfoFlags.InProgress;
                            encryptedData.Advance(b.Span.Length);
                        }
                    }
                }
                encryptedData.Ensure(16);
                encryptedData.Write(new Span<byte>(tag,16));
            }
        }
        public unsafe void DecryptFrame(ref ReadableBuffer buffer, ulong sequenceNumber, byte[] nounce)
        {
            var originalBuffer = buffer;
            //Additional data 
            var additionalData = stackalloc byte[13];
            var spanAdditional = new Span<byte>(additionalData, 13);
            spanAdditional.Write64BitNumber(sequenceNumber);
            spanAdditional = spanAdditional.Slice(8);
            buffer.Slice(0, 3).CopyTo(spanAdditional);
            spanAdditional = spanAdditional.Slice(3);
            var newLength = buffer.Slice(3, 2).ReadBigEndian<ushort>() - 16 - 8;
            spanAdditional.Write16BitNumber((ushort)newLength);
            buffer = buffer.Slice(5);
            var nSpan = new Span<byte>(nounce, 4);
            buffer.Slice(0, 8).CopyTo(nSpan);

            if (buffer.IsSingleSpan)
            {
                
                void* outputBuffer;
                buffer.First.TryGetPointer(out outputBuffer);
                buffer = buffer.Slice(8);
                //Nounce done, now the actual data
                void* encryptedData;
                void* authTag;
                int dataLength = buffer.Length - 16;
                buffer.First.TryGetPointer(out encryptedData);
                buffer.Slice(dataLength).First.TryGetPointer(out authTag);
                fixed (byte* nPtr = nounce)
                {
                    var cInfo = new InteropStructs.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
                    cInfo.cbNonce = nounce.Length;
                    cInfo.pbNonce = (IntPtr)nPtr;
                    cInfo.dwInfoVersion = 1;
                    cInfo.cbSize = Marshal.SizeOf(typeof(InteropStructs.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));
                    cInfo.pbTag = (IntPtr)authTag;
                    cInfo.cbTag = 16;
                    cInfo.cbAuthData = 13;
                    cInfo.pbAuthData = (IntPtr)additionalData;

                    cInfo.dwFlags = InteropStructs.AuthenticatedCipherModeInfoFlags.None;
                    int resultSize;
                    Interop.CheckReturnOrThrow(
                    Interop.BCryptDecrypt(_keyHandle, encryptedData, dataLength, &cInfo, null, 0, outputBuffer
                    , dataLength, out resultSize, 0));
                    buffer = originalBuffer.Slice(0, originalBuffer.Length - 16 - 8);
                    return;
                }
            }
            else
            {
                int blockLength = InteropProperties.GetBlockLength(_keyHandle);
                var iv = stackalloc byte[blockLength];
                throw new NotImplementedException();
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
        
        

        public void Dispose()
        {
            throw new NotImplementedException();
        }
    }
}
