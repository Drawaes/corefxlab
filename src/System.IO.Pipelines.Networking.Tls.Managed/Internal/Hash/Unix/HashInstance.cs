using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Unix;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
using static System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Unix.InteropHash;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash.Unix
{
    internal class HashInstance : IHashInstance
    {
        private SafeEvpMdCtxHandle _hashPointer;
        private IntPtr _hashProvider;
        private int _hashLength;

        public HashInstance(int hashLength, IntPtr hashProvider)
        {
            _hashProvider = hashProvider;
            _hashLength = hashLength;
            _hashPointer = EVP_MD_CTX_create();
            ExceptionHelper.CheckOpenSslError(EVP_DigestInit_ex(_hashPointer, hashProvider,IntPtr.Zero));
        }

        public int HashLength => _hashLength;

        public unsafe void Finish(byte* output, int length, bool completed)
        {
            if (completed)
            {
                ExceptionHelper.CheckOpenSslError(EVP_DigestFinal_ex(_hashPointer, (IntPtr)output, ref length));
                Dispose();
            }
            else
            {
                using (var tmp = EVP_MD_CTX_create())
                {
                    ExceptionHelper.CheckOpenSslError(EVP_MD_CTX_copy_ex(tmp, _hashPointer));
                    ExceptionHelper.CheckOpenSslError(EVP_DigestFinal_ex(tmp, (IntPtr)output, ref length));
                }
            }
        }

        public unsafe void HashData(byte* buffer, int length)
        {
            ExceptionHelper.CheckOpenSslError(EVP_DigestUpdate(_hashPointer, (IntPtr)buffer, length));
        }

        ~HashInstance()
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
