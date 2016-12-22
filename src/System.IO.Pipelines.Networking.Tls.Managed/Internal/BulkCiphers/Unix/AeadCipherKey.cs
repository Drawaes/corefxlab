using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Unix;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.TlsSpec;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
using static System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Unix.InteropBulkCiphers;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.BulkCiphers.Unix
{
    internal unsafe class AeadCipherKey : IBulkCipherInstance
    {
        private IntPtr _keyPointer;
        private IntPtr _cipher;
        private byte[] _nonceBuffer;
        private ulong _sequenceNumber;

        public AeadCipherKey(byte* key, int keyLength, IntPtr cipher)
        {
            _keyPointer = Marshal.AllocHGlobal(keyLength);
            var span = new Span<byte>(key, keyLength);
            var spanDest = new Span<byte>((void*)_keyPointer, keyLength);
            span.CopyTo(spanDest);
            _cipher = cipher;
        }

        public int TrailerSize => Tls12Utils.AEAD_TAG_LENGTH;
        public int ExplicitNonceSize => sizeof(ulong);
        public byte[] HmacKey { set { } }

        public void Encrypt(ref WritableBuffer buffer, ReadableBuffer plainText, TlsFrameType frameType, ConnectionState state)
        {
            var additionalData = stackalloc byte[13];
            var additionalSpan = new Span<byte>(additionalData, 13);
            additionalSpan.Write64BitNumber(_sequenceNumber);
            additionalSpan = additionalSpan.Slice(8);
            additionalSpan.Write(frameType);
            additionalSpan = additionalSpan.Slice(1);
            additionalSpan.Write(Tls12Utils.TLS_VERSION);
            additionalSpan = additionalSpan.Slice(2);
            additionalSpan.Write16BitNumber((ushort)plainText.Length);

            fixed (byte* noncePtr = _nonceBuffer)
            {
                var totalDataLength = plainText.Length;
                using (var ctx = EVP_CIPHER_CTX_new())
                {
                    ExceptionHelper.CheckOpenSslError(EVP_EncryptInit_ex(ctx, _cipher, IntPtr.Zero, (byte*)_keyPointer, noncePtr));
                    int resultSize = 0;
                    ExceptionHelper.CheckOpenSslError(EVP_EncryptUpdate(ctx, null, ref resultSize, additionalData, 13));
                    foreach (var b in plainText)
                    {
                        totalDataLength = totalDataLength - b.Length;
                        if (b.Length == 0 && totalDataLength > 0)
                        {
                            continue;
                        }
                        void* inPointer;
                        if (!b.TryGetPointer(out inPointer))
                        {
                            throw new NotImplementedException("Need to implement a pinned array if we can't get a pointer");
                        }
                        int amountWritten = b.Length;
                        ExceptionHelper.CheckOpenSslError(EVP_EncryptUpdate(ctx, inPointer, ref amountWritten, inPointer, amountWritten));
                    }
                    int result = 0;
                    ExceptionHelper.CheckOpenSslError(EVP_EncryptFinal_ex(ctx, null, ref result));
                    buffer.Ensure(Tls12Utils.AEAD_TAG_LENGTH);
                    void* tagPointer;
                    if (!buffer.Memory.TryGetPointer(out tagPointer))
                    {
                        throw new NotImplementedException();
                    }
                    ExceptionHelper.CheckCtrlForError(EVP_CIPHER_CTX_ctrl(ctx, EVP_CIPHER_CTRL.EVP_CTRL_GCM_GET_TAG, Tls12Utils.AEAD_TAG_LENGTH, tagPointer));
                    buffer.Advance(Tls12Utils.AEAD_TAG_LENGTH);
                    var nouceSpan = new Span<byte>(noncePtr + 4, 8);
                    _sequenceNumber++;
                    nouceSpan.Write64BitNumber(_sequenceNumber);
                }
            }
        }

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

        public void DecryptFrame(ReadableBuffer buffer, ref WritableBuffer writer)
        {
            var additionalData = stackalloc byte[13];
            var spanAdditional = new Span<byte>(additionalData, 13);
            spanAdditional.Write64BitNumber(_sequenceNumber);
            _sequenceNumber++;
            spanAdditional = spanAdditional.Slice(8);
            buffer.Slice(0, 3).CopyTo(spanAdditional);
            spanAdditional = spanAdditional.Slice(3);
            var newLength = buffer.Slice(3, 2).ReadBigEndian<ushort>() - Tls12Utils.AEAD_TAG_LENGTH - 8;
            spanAdditional.Write16BitNumber((ushort)newLength);
            buffer = buffer.Slice(5);
            var nSpan = new Span<byte>(_nonceBuffer);
            buffer.Slice(0, 8).CopyTo(nSpan.Slice(4));
            buffer = buffer.Slice(8);
            var nPtr = stackalloc byte[_nonceBuffer.Length];
            nSpan.CopyTo(new Span<byte>(nPtr, _nonceBuffer.Length));
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
                using (var ctx = EVP_CIPHER_CTX_new())
                {
                    ExceptionHelper.CheckOpenSslError(EVP_EncryptInit_ex(ctx, _cipher, IntPtr.Zero, (byte*)_keyPointer, nPtr));
                    int resultSize = 0;
                    ExceptionHelper.CheckOpenSslError(EVP_DecryptUpdate(ctx, null, ref resultSize, additionalData, 13));
                    int amountToWrite = cipherText.Length;
                    foreach (var b in cipherText)
                    {
                        amountToWrite -= b.Length;
                        if (b.Length == 0 && b.Length == 0)
                        {
                            continue;
                        }
                        bool isLast = amountToWrite == 0;
                        WriteBlock(ctx, ref writer, b);
                    }
                    int result = 0;
                    ExceptionHelper.CheckOpenSslError(EVP_DecryptFinal_ex(ctx, null, ref result));
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

        private unsafe void WriteBlock(SafeEvpCipherCtxHandle ctx, ref WritableBuffer writeBuffer, Memory<byte> dataToWrite)
        {
            writeBuffer.Ensure(dataToWrite.Length);
            void* output;
            if (!writeBuffer.Memory.TryGetPointer(out output))
            {
                throw new NotImplementedException();
            }
            void* input;
            if (!dataToWrite.TryGetPointer(out input))
            {
                throw new NotImplementedException();
            }
            int result = dataToWrite.Length;
            ExceptionHelper.CheckOpenSslError(EVP_DecryptUpdate(ctx, output, ref result, input, result));
            writeBuffer.Advance(result);
        }

        ~AeadCipherKey()
        {
            Dispose();
        }

        public void Dispose()
        {
            if (_keyPointer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(_keyPointer);
                _keyPointer = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }
    }
}
