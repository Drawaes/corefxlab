using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Windows;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using static System.IO.Pipelines.Networking.Tls.Managed.Internal.Windows.InteropStructs;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.BulkCipher
{
    public class BulkCipherInstance : IDisposable
    {
        private OwnedMemory<byte> _buffer;
        private IntPtr _handle;
        private int _maxTagLength;
        private int _blockLength;
        private byte[] _nounce;
        private ulong _sequenceNumber;

        public unsafe BulkCipherInstance(IntPtr provider, OwnedMemory<byte> buffer, byte* keyPointer, int keyLength)
        {
            try
            {
                _buffer = buffer;
                _handle = InteropBulkEncryption.ImportKey(provider, buffer.Memory, keyPointer, keyLength);
                _blockLength = InteropProperties.GetBlockLength(_handle);
                _maxTagLength = InteropProperties.GetMaxAuthTagLength(_handle);
            }
            catch
            {
                Dispose();
                throw;
            }
        }

        public ulong SequenceNumber => _sequenceNumber;

        public unsafe void DecryptFrame(ref ReadableBuffer buffer)
        {
            var originalBuffer = buffer;
            //Additional data 
            var additionalData = stackalloc byte[13];
            var spanAdditional = new Span<byte>(additionalData, 13);
            spanAdditional.Write64BitNumber(_sequenceNumber);
            _sequenceNumber++;
            spanAdditional = spanAdditional.Slice(8);
            buffer.Slice(0, 3).CopyTo(spanAdditional);
            spanAdditional = spanAdditional.Slice(3);
            var newLength = buffer.Slice(3, 2).ReadBigEndian<ushort>() - 16 - 8;
            spanAdditional.Write16BitNumber((ushort)newLength);
            buffer = buffer.Slice(5);
            var nSpan = new Span<byte>(_nounce, 4);
            buffer.Slice(0, 8).CopyTo(nSpan);
            if (buffer.IsSingleSpan)
            {

                void* outputBuffer;
                var outputBookMark = buffer;
                buffer.First.TryGetPointer(out outputBuffer);
                buffer = buffer.Slice(8);
                //Nounce done, now the actual data
                void* encryptedData;
                void* authTag;
                int dataLength = buffer.Length - 16;
                buffer.First.TryGetPointer(out encryptedData);
                buffer.Slice(dataLength).First.TryGetPointer(out authTag);
                fixed (byte* nPtr = _nounce)
                {
                    var cInfo = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
                    cInfo.cbNonce = _nounce.Length;
                    cInfo.pbNonce = (IntPtr)nPtr;
                    cInfo.dwInfoVersion = 1;
                    cInfo.cbSize = Marshal.SizeOf<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>();
                    cInfo.pbTag = (IntPtr)authTag;
                    cInfo.cbTag = 16;
                    cInfo.cbAuthData = 13;
                    cInfo.pbAuthData = (IntPtr)additionalData;

                    cInfo.dwFlags = AuthenticatedCipherModeInfoFlags.None;
                    int resultSize;
                    ExceptionHelper.CheckReturnCode(
                        InteropBulkEncryption.BCryptDecrypt(_handle, encryptedData, dataLength, &cInfo, null, 0, outputBuffer, dataLength, out resultSize, 0));
                    buffer = originalBuffer.Slice(0, resultSize + 5);
                    return;
                }
            }
            else
            {
                //int blockLength = InteropProperties.GetBlockLength(_keyHandle);
                //var iv = stackalloc byte[blockLength];
                throw new NotImplementedException();
            }
        }

        public unsafe byte[] Encrypt(byte[] plainText, byte[] additionalData, out byte[] authTagResult)
        {
            var nSpan = new Span<byte>(_nounce,4);
            nSpan.Write64BitNumber(_sequenceNumber);
            _sequenceNumber++;

            var cInfo = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
            cInfo.dwInfoVersion = 1;
            cInfo.cbSize = Marshal.SizeOf<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>();

            var tag = new byte[16];
            var cipherText = new byte[plainText.Length];
            var block = stackalloc byte[16];
            fixed (void* nPtr = _nounce)
            fixed (void* pPtr = plainText)
            fixed (void* aPtr = additionalData)
            fixed (void* tPtr = tag)
            fixed (void* cPtr = cipherText)
            {
                cInfo.cbAuthData = additionalData.Length;
                cInfo.cbNonce = _nounce.Length;
                cInfo.cbTag = tag.Length;
                cInfo.dwFlags = AuthenticatedCipherModeInfoFlags.None;
                cInfo.pbAuthData = (IntPtr)aPtr;
                cInfo.pbNonce = (IntPtr)nPtr;
                cInfo.pbTag = (IntPtr)tPtr;

                int amountWritten = 0;
                ExceptionHelper.CheckReturnCode(InteropBulkEncryption.BCryptEncrypt(_handle, pPtr, plainText.Length, &cInfo, null, 0, cPtr, cipherText.Length, out amountWritten, 0));
            }
            authTagResult = tag;
            return cipherText;
        }

        public void Dispose()
        {
            if (_buffer != null)
            {
                _buffer.Dispose();
                _buffer = null;
            }

        }

        internal void SetNouce(Span<byte> nounce)
        {
            _nounce = new byte[12];
            nounce.CopyTo(_nounce);
        }
    }
}
