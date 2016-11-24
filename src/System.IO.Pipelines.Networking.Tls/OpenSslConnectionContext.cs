﻿using System.IO.Pipelines.Networking.Tls.Internal.OpenSsl;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls
{
    public class OpenSslConnectionContext : ISecureContext
    {
        private static readonly Task CachedTask = Task.FromResult(0);

        private readonly OpenSslSecurityContext _securityContext;
        private int _headerSize = 5; //5 is the minimum (1 for frame type, 2 for version, 2 for frame size)
        private int _trailerSize = 16; //Used for MAC storage
        private bool _readyToSend;
        private IntPtr _ssl;
        private readonly InteropBio.BioHandle _readBio;
        private readonly InteropBio.BioHandle _writeBio;
        private ApplicationProtocols.ProtocolIds _negotiatedProtocol;

        public OpenSslConnectionContext(OpenSslSecurityContext securityContext, IntPtr ssl)
        {
            _ssl = ssl;
            _securityContext = securityContext;
            _writeBio = InteropBio.BIO_new(CustomBio.Custom());
            _readBio = InteropBio.BIO_new(CustomBio.Custom());

            Interop.SSL_set_bio(_ssl, _readBio, _writeBio);
            if (IsServer)
            {
                Interop.SSL_set_accept_state(_ssl);
            }
            else
            {
                Interop.SSL_set_connect_state(_ssl);
            }
        }

        public bool IsServer => _securityContext.IsServer;

        public int HeaderSize
        {
            get { return _headerSize; }
            set { _headerSize = value; }
        }

        public int TrailerSize
        {
            get { return _trailerSize; }
            set { _trailerSize = value; }
        }

        public ApplicationProtocols.ProtocolIds NegotiatedProtocol => _negotiatedProtocol;
        public bool ReadyToSend => _readyToSend;
        public CipherInfo CipherInfo => _ssl != IntPtr.Zero ? Interop.GetCipherInfo(_ssl) : default(CipherInfo);

        public unsafe Task DecryptAsync(ReadableBuffer encryptedData, IPipelineWriter decryptedPipeline)
        {
            CustomBio.SetReadBufferPointer(_readBio, ref encryptedData);

            var decryptedData = decryptedPipeline.Alloc();
            var result = 1;
            while (result > 0)
            {
                void* memPtr;
                decryptedData.Ensure(1024);

                decryptedData.Memory.TryGetPointer(out memPtr);
                result = Interop.SSL_read(_ssl, memPtr, decryptedData.Memory.Length);
                if (result > 0)
                {
                    decryptedData.Advance(result);
                }
            }
            return decryptedData.FlushAsync();
        }

        public unsafe Task EncryptAsync(ReadableBuffer unencryptedData, IPipelineWriter encryptedPipeline)
        {
            var handle = GCHandle.Alloc(encryptedPipeline);
            try
            {
                CustomBio.SetWriteBufferPointer(_writeBio, handle);
                while (unencryptedData.Length > 0)
                {
                    void* ptr;
                    unencryptedData.First.TryGetPointer(out ptr);
                    var bytesRead = Interop.SSL_write(_ssl, ptr, unencryptedData.First.Length);
                    unencryptedData = unencryptedData.Slice(bytesRead);
                }
                return encryptedPipeline.Alloc().FlushAsync();
            }
            finally
            {
                CustomBio.NumberOfWrittenBytes(_writeBio);
                handle.Free();
            }
        }

        public Task ProcessContextMessageAsync(IPipelineWriter writer)
        {
            return ProcessContextMessageAsync(default(ReadableBuffer), writer);
        }

        public unsafe Task ProcessContextMessageAsync(ReadableBuffer readBuffer, IPipelineWriter writer)
        {
            var writeHandle = GCHandle.Alloc(writer);
            try
            {
                CustomBio.SetReadBufferPointer(_readBio, ref readBuffer);
                CustomBio.SetWriteBufferPointer(_writeBio, writeHandle);

                var result = Interop.SSL_do_handshake(_ssl);
                if (result == 1)
                {
                    //handshake is complete, do a final write out of data and mark as done
                    //WriteToPipeline(ref writeBuffer, _writeBio);
                    if (_securityContext.AplnBufferLength > 0)
                    {
                        byte* protoPointer;
                        int len;
                        Interop.SSL_get0_alpn_selected(_ssl, out protoPointer, out len);
                        _negotiatedProtocol = ApplicationProtocols.GetNegotiatedProtocol(protoPointer, (byte)len);
                    }
                    _readyToSend = true;
                    if (CustomBio.NumberOfWrittenBytes(_writeBio) > 0)
                    {
                        return writer.Alloc().FlushAsync();
                    }
                    else
                    {
                        return CachedTask;
                    }
                }
                //We didn't get an "okay" message so lets check to see what the actual error was
                var errorCode = Interop.SSL_get_error(_ssl, result);
                if (errorCode == Interop.SslErrorCodes.SSL_NOTHING || errorCode == Interop.SslErrorCodes.SSL_WRITING ||
                    errorCode == Interop.SslErrorCodes.SSL_READING)
                {
                    if (CustomBio.NumberOfWrittenBytes(_writeBio) > 0)
                    {
                        return writer.Alloc().FlushAsync();
                    }
                    else
                    {
                        return CachedTask;
                    }
                }
                throw new InvalidOperationException(
                    $"There was an error during the handshake, error code was {errorCode}");
            }
            catch
            {
                CustomBio.NumberOfWrittenBytes(_writeBio);
                throw;
            }
            finally
            {
                writeHandle.Free();
            }
        }

        public void Dispose()
        {
            if (_ssl != IntPtr.Zero)
            {
                Interop.SSL_free(_ssl);
                _ssl = IntPtr.Zero;
            }
        }
    }
}