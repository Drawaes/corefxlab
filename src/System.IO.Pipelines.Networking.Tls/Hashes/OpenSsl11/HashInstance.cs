using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using static Interop.LibCrypto;

namespace System.IO.Pipelines.Networking.Tls.Hashes.OpenSsl11
{
    public class HashInstance:IHashInstance
    {
        private EVP_MD_CTX _ctx;
        private int _size;

        internal HashInstance(EVP_MD_CTX ctx, int size)
        {
            _ctx = ctx;
            _size = size;
        }

        public int HashLength => _size;
        
        public unsafe int FinishHash(Memory<byte> outputBuffer)
        {
            int size = outputBuffer.Length;
            GCHandle handle;
            var ptr = outputBuffer.GetPointer(out handle);
            try
            {
                ThrowOnError(EVP_DigestFinal_ex(_ctx, ptr , ref size));
                return size;
            }
            finally
            {
                if(handle.IsAllocated)
                {
                    handle.Free();
                }
            }
        }

        public void HashData(ReadableBuffer datatToHash)
        {
            foreach(var m in datatToHash)
            {
                HashData(m);
            }
        }

        public unsafe void HashData(Memory<byte> dataToHash)
        {
            GCHandle handle;
            var ptr = dataToHash.GetPointer(out handle);
            try
            {
                ThrowOnError(EVP_DigestUpdate(_ctx, ptr, dataToHash.Length));
            }
            finally
            {
                if (handle.IsAllocated)
                {
                    handle.Free();
                }
            }
        }

        public int InterimHash(Memory<byte> outputBuffer)
        {
            throw new NotImplementedException();
        }
        
        public void Dispose()
        {
            _ctx.Free();
        }

        ~HashInstance()
        {
            Dispose();
        }
    }
}
