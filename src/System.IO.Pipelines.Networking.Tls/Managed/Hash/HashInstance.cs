using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Internal.ManagedTls;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Hash
{
    public unsafe struct HashInstance : IDisposable
    {
        private OwnedMemory<byte> _buffer;
        private IntPtr _hashHandle;

        public HashInstance(IntPtr providerHandle, OwnedMemory<byte> buffer)
        {
            try
            {
                _buffer = buffer;
                IntPtr handle;
                void* memPointer;
                if (!_buffer.Memory.TryGetPointer(out memPointer))
                {
                    throw new InvalidOperationException("Problem getting the pointer for a native memory block");
                }

                Interop.CheckReturnOrThrow(Interop.BCryptCreateHash(providerHandle, out handle, memPointer, buffer.Length, null, 0, 0));
                _hashHandle = handle;
            }
            catch
            {
                buffer.Release();
                throw;
            }
        }

        public void HashData(ReadableBuffer buffer)
        {
            foreach (var memory in buffer)
            {
                void* pointer;
                if (!memory.TryGetPointer(out pointer))
                {
                    throw new InvalidOperationException("Problem getting the pointer for a native memory block");
                }
                Interop.CheckReturnOrThrow(Interop.BCryptHashData(_hashHandle, pointer, memory.Length, 0));
            }
        }
        public void HashData(byte[] buffer)
        {
            fixed (byte* ptr = buffer)
            {
                Interop.CheckReturnOrThrow(Interop.BCryptHashData(_hashHandle, ptr, buffer.Length, 0));
            }
        }

        public void Dispose()
        {
            if (_hashHandle != IntPtr.Zero)
            {
                try
                {
                    Interop.BCryptDestroyHash(_hashHandle);
                    _hashHandle = IntPtr.Zero;
                }
                catch
                {

                }
            }
            if (_buffer != null)
            {
                _buffer.Release();
                _buffer = null;
            }
        }

        internal byte[] Finish()
        {
            int length = InteropProperties.GetHashLength(_hashHandle);
            byte[] returnValue = new byte[length];
            fixed (void* ptr = returnValue)
            {
                Interop.CheckReturnOrThrow(Interop.BCryptFinishHash(_hashHandle, ptr, length, 0));
                _hashHandle = IntPtr.Zero;
            }
            Dispose();
            return returnValue;
        }
    }
}
