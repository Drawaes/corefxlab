using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Windows;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash.Windows
{
    internal class HashInstance : IHashInstance
    {
        private NativeBufferPool _pool;
        private OwnedMemory<byte> _buffer;
        private SafeBCryptHashHandle _hashHandle;
        private int _stateSize;
        private SafeBCryptAlgorithmHandle _providerHandle;
        private int _hashSize;

        public HashInstance(SafeBCryptAlgorithmHandle providerHandle, byte[] key, NativeBufferPool pool, int stateSize, int hashSize)
        {
            _pool = pool;
            _stateSize = stateSize;
            if (pool != null)
            {
                _buffer = pool.Rent(stateSize);
            }
            _providerHandle = providerHandle;
            _hashSize = hashSize;
            try
            {
                _hashHandle = Internal.Windows.BCryptHashHelper.CreateHash(_providerHandle, key, _buffer?.Memory);
            }
            catch
            {
                pool.Return(_buffer);
                _buffer = null;
                throw;
            }
        }

        public int HashLength => _hashSize;

        public unsafe void HashData(byte* buffer, int length)
        {
            Internal.Windows.BCryptHashHelper.HashData(_hashHandle, buffer, length);
        }

        public unsafe void Finish(byte* output, int length, bool completed)
        {
            if (!completed)
            {
                var tmpBuffer = _pool.Rent(_stateSize);
                try
                {
                    using (var tempHash = Internal.Windows.BCryptHashHelper.Duplicate(_hashHandle, tmpBuffer.Memory))
                    {
                        Internal.Windows.BCryptHashHelper.FinishHash(tempHash, output, length);
                    }
                }
                finally
                {
                    _pool.Return(tmpBuffer);
                }
            }
            else
            {
                Internal.Windows.BCryptHashHelper.FinishHash(_hashHandle, output, length);
                Dispose();
            }
        }

        ~HashInstance()
        {
            Dispose();
        }

        public void Dispose()
        {
            _hashHandle?.Dispose();
            if (_buffer != null)
            {
                _pool.Return(_buffer);
                _buffer = null;
            }
            GC.SuppressFinalize(this);
        }
    }
}
