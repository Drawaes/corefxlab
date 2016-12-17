using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Windows;
using System.Linq;
using System.Runtime.CompilerServices;
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
        private byte[] _nounceBuffer;
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
            var nSpan = new Span<byte>(_nounceBuffer, 4);
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
                fixed (byte* nPtr = _nounceBuffer)
                {
                    var cInfo = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
                    cInfo.cbNonce = _nounceBuffer.Length;
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

        internal unsafe void Encrypt(ref WritableBuffer buffer, ReadableBuffer plainText, TlsFrameType frameType)
        {
            var additionalData = stackalloc byte[13];
            var additionalSpan = new Span<byte>(additionalData,13);
            additionalSpan.Write64BitNumber(_sequenceNumber);
            additionalSpan = additionalSpan.Slice(8);
            additionalSpan.Write(frameType);
            additionalSpan = additionalSpan.Slice(1);
            additionalSpan.Write((ushort)0x0303);
            additionalSpan = additionalSpan.Slice(2);
            additionalSpan.Write16BitNumber((ushort)plainText.Length);
            buffer.Ensure(8);
            buffer.WriteBigEndian(_sequenceNumber);

            fixed(byte* nouncePtr = _nounceBuffer)
            {
                var cInfo = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
                cInfo.dwInfoVersion = 1;
                cInfo.cbSize = Marshal.SizeOf<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>();
                cInfo.cbNonce = _nounceBuffer.Length;
                cInfo.pbNonce = (IntPtr)nouncePtr;
                var iv = stackalloc byte[_blockLength];
                var macRecord = stackalloc byte[_maxTagLength];
                var tag = stackalloc byte[16];
                cInfo.dwFlags = AuthenticatedCipherModeInfoFlags.ChainCalls;
                cInfo.cbMacContext = _maxTagLength;
                cInfo.pbMacContext = (IntPtr)macRecord;
                cInfo.pbTag = (IntPtr)tag;
                cInfo.cbTag = 16;
                cInfo.pbAuthData = (IntPtr)additionalData;
                cInfo.cbAuthData = 13;
                var totalDataLength = plainText.Length;
                foreach (var b in plainText)
                {
                    totalDataLength = totalDataLength - b.Length;
                    if (b.Length > 0 || totalDataLength == 0)
                    {
                        if (totalDataLength == 0)
                        {
                            cInfo.dwFlags = AuthenticatedCipherModeInfoFlags.None;
                        }
                    }
                    buffer.Ensure(b.Length);
                    void* outPointer;
                    if (!buffer.Memory.TryGetPointer(out outPointer))
                    {
                        throw new NotImplementedException("Need to implement a pinned array if we can get a pointer");
                    }
                    int amountWritten;
                    ExceptionHelper.CheckReturnCode(InteropBulkEncryption.BCryptEncrypt(_handle, outPointer, b.Length, &cInfo, iv, (uint)_blockLength, outPointer, b.Length, out amountWritten, 0));
                    buffer.Advance(amountWritten);
                    cInfo.dwFlags = AuthenticatedCipherModeInfoFlags.InProgress;
                    if (totalDataLength == 0)
                    {
                        break;
                    }
                }
                buffer.Ensure(16);
                buffer.Write(new Span<byte>(tag, 16));

                var nouceSpan = new Span<byte>(nouncePtr + 4, 8);
                _sequenceNumber++;
                nouceSpan.Write64BitNumber(_sequenceNumber);
            }
        }

        internal unsafe void Encrypt(ref WritableBuffer buffer, int encryptedDataStart, byte[] additionalData)
        {
            var amountOfDataToEncrypt = buffer.BytesWritten - encryptedDataStart;
            fixed(byte* nouncePtr = _nounceBuffer)
            fixed(byte* authPtr = additionalData)
            {
                var cInfo = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
                cInfo.dwInfoVersion = 1;
                cInfo.cbSize = Marshal.SizeOf<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>();
                cInfo.cbNonce = _nounceBuffer.Length;
                cInfo.pbNonce = (IntPtr)nouncePtr;

                var iv = stackalloc byte[_blockLength];
                var macRecord = stackalloc byte[_maxTagLength];
                var tag = stackalloc byte[16];
                cInfo.dwFlags = AuthenticatedCipherModeInfoFlags.ChainCalls;
                cInfo.cbMacContext = _maxTagLength;
                cInfo.pbMacContext = (IntPtr)macRecord;
                cInfo.pbTag = (IntPtr) tag;
                cInfo.cbTag = 16;
                cInfo.pbAuthData = (IntPtr) authPtr;
                cInfo.cbAuthData = additionalData.Length;
                var totalDataLength = buffer.BytesWritten - encryptedDataStart;
                foreach (var b in buffer.AsReadableBuffer().Slice(encryptedDataStart))
                {
                    totalDataLength = totalDataLength - b.Length;
                    if (b.Length > 0 || totalDataLength == 0)
                    {
                        if (totalDataLength == 0)
                        {
                            cInfo.dwFlags = AuthenticatedCipherModeInfoFlags.None;
                        }
                        void* outPointer;
                        if(!b.TryGetPointer(out outPointer))
                        {
                            throw new NotImplementedException("Need to implement a pinned array if we can get a pointer");
                        }
                        int amountWritten;
                        ExceptionHelper.CheckReturnCode(InteropBulkEncryption.BCryptEncrypt(_handle, outPointer, b.Length, &cInfo, iv, (uint)_blockLength, outPointer, b.Length, out amountWritten, 0));
                        cInfo.dwFlags = InteropStructs.AuthenticatedCipherModeInfoFlags.InProgress;
                        if(totalDataLength == 0)
                        {
                            break;
                        }
                    }
                }
                buffer.Ensure(16);
                buffer.Write(new Span<byte>(tag,16));

                var nouceSpan = new Span<byte>(nouncePtr + 4,8);
                _sequenceNumber ++;
                nouceSpan.Write64BitNumber(_sequenceNumber);
            }
        }
        
        public void Dispose()
        {
            if(_handle != IntPtr.Zero)
            {
                InteropBulkEncryption.DestroyKey(_handle);
                _handle = IntPtr.Zero;
            }
            if (_buffer != null)
            {
                _buffer.Release();
                _buffer = null;
            }
            GC.SuppressFinalize(this);
        }

        ~BulkCipherInstance()
        {
            Dispose();
        }

        internal void SetNouce(Span<byte> nounce)
        {
            _nounceBuffer = new byte[12];
            nounce.CopyTo(_nounceBuffer);
        }
    }
}
