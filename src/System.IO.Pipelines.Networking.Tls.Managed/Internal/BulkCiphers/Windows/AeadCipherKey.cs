using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Windows;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.TlsSpec;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Windows;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
using static global::Interop.BCrypt;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.BulkCiphers.Windows
{
    internal sealed class AeadCipherKey : IBulkCipherInstance
    {
        private NativeBufferPool _pool;
        private SafeBCryptKeyHandle _handle;
        private byte[] _nonceBuffer;
        private ulong _sequenceNumber;
        private OwnedMemory<byte> _buffer;
        private int _blockLength;
        private int _maxTagLength;

        public unsafe AeadCipherKey(SafeBCryptAlgorithmHandle provider, NativeBufferPool pool, int bufferSizeNeeded, byte* keyPointer, int keyLength)
        {
            _pool = pool;
            _buffer = pool.Rent(bufferSizeNeeded);
            try
            {
                _handle = BCryptHelper.ImportKey(provider, _buffer.Memory, keyPointer, keyLength);
                _blockLength = BCryptPropertiesHelper.GetBlockLength(_handle);
                _maxTagLength = BCryptPropertiesHelper.GetMaxAuthTagLength(_handle);
            }
            catch
            {
                Dispose();
                throw;
            }
        }

        public byte[] HmacKey { get; set; }

        public int TrailerSize => Tls12Utils.AEAD_TAG_LENGTH;

        public int ExplicitNonceSize => sizeof(ulong);

        public void SetNonce(Span<byte> nounce)
        {
            _nonceBuffer = new byte[12];
            nounce.CopyTo(_nonceBuffer);
        }

        public void WriteExplicitNonce(ref WritableBuffer buffer)
        {
            buffer.Ensure(8);
            buffer.Write(new Span<byte>(_nonceBuffer, 4));
        }

        public unsafe void Encrypt(ref WritableBuffer buffer, ReadableBuffer plainText, TlsFrameType frameType, IConnectionState state)
        {
            var addInfo = new AdditionalInformation(_sequenceNumber, (ushort)plainText.Length, frameType);
            
            fixed (byte* noncePtr = _nonceBuffer)
            {
                var cInfo = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
                cInfo.dwInfoVersion = 1;
                cInfo.cbSize = sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO);
                cInfo.cbNonce = _nonceBuffer.Length;
                cInfo.pbNonce = (IntPtr)noncePtr;
                var iv = stackalloc byte[_blockLength];
                var macRecord = stackalloc byte[_maxTagLength];
                var tag = stackalloc byte[Tls12Utils.AEAD_TAG_LENGTH];
                cInfo.dwFlags = AuthenticatedCipherModeInfoFlags.ChainCalls;
                cInfo.cbMacContext = _maxTagLength;
                cInfo.pbMacContext = (IntPtr)macRecord;
                cInfo.pbTag = (IntPtr)tag;
                cInfo.cbTag = Tls12Utils.AEAD_TAG_LENGTH;
                cInfo.pbAuthData = &addInfo;
                cInfo.cbAuthData = sizeof(AdditionalInformation);
                var totalDataLength = plainText.Length;
                foreach (var b in plainText)
                {
                    totalDataLength = totalDataLength - b.Length;
                    if (b.Length == 0 && totalDataLength > 0)
                    {
                        continue;
                    }
                    if (totalDataLength == 0)
                    {
                        cInfo.dwFlags = AuthenticatedCipherModeInfoFlags.None;
                    }
                    void* inPointer;
                    if (!b.TryGetPointer(out inPointer))
                    {
                        throw new NotImplementedException("Need to implement a pinned array if we can't get a pointer");
                    }
                    int amountWritten;
                    ExceptionHelper.CheckReturnCode(BCryptEncrypt(_handle, inPointer, b.Length, &cInfo, iv, _blockLength, inPointer, b.Length, out amountWritten, 0));
                    cInfo.dwFlags = AuthenticatedCipherModeInfoFlags.InProgress;
                    if (totalDataLength == 0)
                    {
                        break;
                    }
                }
                buffer.Ensure(16);
                buffer.Write(new Span<byte>(tag, Tls12Utils.AEAD_TAG_LENGTH));

                var nouceSpan = new Span<byte>(noncePtr + 4, 8);
                _sequenceNumber++;
                nouceSpan.Write64BitBigEndian(_sequenceNumber);
            }
        }

        public unsafe void DecryptFrame(ReadableBuffer buffer, ref WritableBuffer writer)
        {
            var frameType = buffer.ReadBigEndian<TlsFrameType>();
            var newLength = buffer.Slice(3, 2).ReadBigEndian<ushort>() - Tls12Utils.AEAD_TAG_LENGTH - 8;
            var addInfo = new AdditionalInformation(_sequenceNumber,(ushort)newLength, frameType);
            _sequenceNumber++;
            buffer = buffer.Slice(5);
            var nSpan = new Span<byte>(_nonceBuffer, 4);
            buffer.Slice(0, 8).CopyTo(nSpan);
            buffer = buffer.Slice(8);

            var cipherText = buffer.Slice(0, newLength);

            var authTag = buffer.Slice(newLength, Tls12Utils.AEAD_TAG_LENGTH);
            void* authPtr;
            GCHandle authHandle = default(GCHandle);
            try
            {
                if (authTag.IsSingleSpan)
                {
                    if (!authTag.First.TryGetPointer(out authPtr))
                    {
                        throw new NotImplementedException();
                    }
                }
                else
                {
                    var authTagArray = authTag.ToArray();
                    authHandle = GCHandle.Alloc(authTagArray, GCHandleType.Pinned);
                    authPtr = (void*)authHandle.AddrOfPinnedObject();
                }

                var cInfo = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
                cInfo.dwInfoVersion = 1;
                cInfo.cbSize = Marshal.SizeOf<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>();
                cInfo.cbAuthData = 13;
                cInfo.pbAuthData = &addInfo;
                cInfo.pbTag = (IntPtr)authPtr;
                cInfo.cbTag = Tls12Utils.AEAD_TAG_LENGTH;
                cInfo.dwFlags = AuthenticatedCipherModeInfoFlags.ChainCalls;
                var iv = stackalloc byte[_blockLength];
                var macRecord = stackalloc byte[_maxTagLength];
                cInfo.cbMacContext = _maxTagLength;
                cInfo.pbMacContext = (IntPtr)macRecord;

                fixed (void* nPtr = _nonceBuffer)
                {
                    cInfo.cbNonce = _nonceBuffer.Length;
                    cInfo.pbNonce = (IntPtr)nPtr;

                    int amountToWrite = cipherText.Length;
                    foreach (var b in cipherText)
                    {
                        amountToWrite -= b.Length;
                        if (b.Length == 0 && b.Length == 0)
                        {
                            continue;
                        }
                        bool isLast = amountToWrite == 0;
                        WriteBlock(ref writer, b, ref cInfo, isLast, iv);
                    }
                }
            }
            finally
            {
                if (authHandle.IsAllocated)
                {
                    authHandle.Free();
                }
            }
        }

        private unsafe void WriteBlock(ref WritableBuffer writeBuffer, Memory<byte> dataToWrite, ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info, bool isLast, byte* ivPtr)
        {
            if (isLast)
            {
                info.dwFlags = AuthenticatedCipherModeInfoFlags.None;
            }
            writeBuffer.Ensure(dataToWrite.Length);
            void* output;
            var handleIn = default(GCHandle);
            var handleOut = default(GCHandle);
            try
            {
                if (!writeBuffer.Memory.TryGetPointer(out output))
                {
                    ArraySegment<byte> segment;
                    if (!writeBuffer.Memory.TryGetArray(out segment))
                    {
                        Debug.Assert(false,"Unable to get pointer or array");
                    }
                    handleOut = GCHandle.Alloc(segment.Array,GCHandleType.Pinned);
                    output = IntPtr.Add(handleOut.AddrOfPinnedObject(),segment.Offset).ToPointer();
                }
                void* input;
                if (!dataToWrite.TryGetPointer(out input))
                {
                    ArraySegment<byte> segWrite;
                    if (!dataToWrite.TryGetArray(out segWrite))
                    {
                        Debug.Assert(false, "Unable to get pointer or array");
                    }
                    handleIn = GCHandle.Alloc(segWrite.Array,GCHandleType.Pinned);
                    input = IntPtr.Add(handleIn.AddrOfPinnedObject(),segWrite.Offset).ToPointer();
                }
                int result;
                ExceptionHelper.CheckReturnCode(
                    BCryptDecrypt(_handle, input, dataToWrite.Length, Unsafe.AsPointer(ref info), ivPtr, _blockLength, output, dataToWrite.Length, out result, 0));
                writeBuffer.Advance(result);
            }
            finally
            {
                if(handleIn.IsAllocated)
                {
                    handleIn.Free();
                }
                if(handleOut.IsAllocated)
                {
                    handleOut.Free();
                }
            }
        }

        ~AeadCipherKey()
        {
            Dispose();
        }

        public void Dispose()
        {
            _handle?.Dispose();
            if (_buffer != null)
            {
                _pool.Return(_buffer);
                _buffer = null;
            }
            GC.SuppressFinalize(this);
        }
    }
}
