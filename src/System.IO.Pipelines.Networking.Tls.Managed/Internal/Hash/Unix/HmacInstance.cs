using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Unix;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
using static System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Unix.InteropHash;


namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash.Unix
{
    public class HmacInstance:IHashInstance
    {
        private SafeEvpMdCtxHandle _hashPointer;
        private int _hashLength;
        private IntPtr _hmacKey;

        public HmacInstance(int hashLength, IntPtr hashProvider, IntPtr buffer, int bufferLen)
        {
            _hashLength = hashLength;
            _hashPointer = EVP_MD_CTX_create();
            _hmacKey = CreateHmacKey(buffer, bufferLen);
            ExceptionHelper.CheckOpenSslError(EVP_DigestSignInit(_hashPointer, IntPtr.Zero, hashProvider, IntPtr.Zero, _hmacKey));
        }

        public int HashLength => _hashLength;

        public unsafe void HashData(byte* buffer, int length)
        {
            ExceptionHelper.CheckOpenSslError(EVP_DigestUpdate(_hashPointer, (IntPtr) buffer, length));
        }

        public unsafe void Finish(byte* output, int length, bool completed)
        {
            if (completed)
            {
                ExceptionHelper.CheckOpenSslError(EVP_DigestSignFinal(_hashPointer, (IntPtr)output, ref length));
                Dispose();
            }
            else
            {
                throw new NotImplementedException();
            }
        }

        ~HmacInstance()
        {
            Dispose();
        }

        public void Dispose()
        {
            _hashPointer.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}
