using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Windows;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash.Windows
{
    public class HashInstance : IHashInstance
    {
        private NativeBufferPool _pool;
        private OwnedMemory<byte> _buffer;
        private IntPtr _hashHandle;
        private int _stateSize;
        private IntPtr _providerHandle;
        private int _hashSize;

        public HashInstance(IntPtr providerHandle, byte[] key, NativeBufferPool pool, int stateSize, int hashSize)
        {
            _pool = pool;
            _stateSize = stateSize;
            _buffer = pool.Rent(stateSize);
            _providerHandle = providerHandle;
            _hashSize = hashSize;
            try
            {
                _hashHandle = InteropHash.CreateHash(_providerHandle, key, _buffer.Memory);
            }
            catch
            {
                pool.Return(_buffer);
                _buffer = null;
                throw;
            }
        }

        public int HashLength => _hashSize;

        public void HashData(ReadableBuffer buffer)
        {
            foreach (var memory in buffer)
            {
                HashData(memory);
            }
        }

        public unsafe void HashData(byte* buffer, int length)
        {
            InteropHash.HashData(_hashHandle, buffer, length);
        }

        public void HashData(Memory<byte> memory)
        {
            InteropHash.HashData(_hashHandle, memory);
        }

        public unsafe void Finish(byte* output, int length, bool completed)
        {
            if (!completed)
            {
                var tmpBuffer = _pool.Rent(_stateSize);
                try
                {
                    var tempHash = InteropHash.Duplicate(_hashHandle, tmpBuffer.Memory);
                    try
                    {
                        InteropHash.FinishHash(tempHash, output, length);
                    }
                    finally
                    {
                        InteropHash.DestroyHash(tempHash);
                    }
                }
                finally
                {
                    _pool.Return(tmpBuffer);
                }
            }
            else
            {
                InteropHash.FinishHash(_hashHandle, output, length);
                Dispose();
            }
        }

        ~HashInstance()
        {
            Dispose();
        }

        public void Dispose()
        {
            if (_hashHandle != IntPtr.Zero)
            {
                try
                {
                    InteropHash.DestroyHash(_hashHandle);
                    _hashHandle = IntPtr.Zero;
                }
                catch
                {
                    //Nom Nom
                }
            }
            if (_buffer != null)
            {
                _pool.Return(_buffer);
                _buffer = null;
            }
            GC.SuppressFinalize(this);
        }
    }
}
