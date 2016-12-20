using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Windows
{
    public unsafe static class InteropRandom
    {
        private const string Dll = "Bcrypt.dll";
        private const uint BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x00000002;

        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern NTResult BCryptGenRandom(IntPtr hAlgorithm, void* pbBuffer, int cbBuffer, uint dwFlags);

        public static void GetRandom(Memory<byte> spanToFill)
        {
            var handle = default(GCHandle);
            try
            {
                void* pointer;
                if (!spanToFill.TryGetPointer(out pointer))
                {
                    ArraySegment<byte> array;
                    spanToFill.TryGetArray(out array);
                    handle = GCHandle.Alloc(array.Array, GCHandleType.Pinned);
                    pointer = ((byte*)handle.AddrOfPinnedObject() + array.Offset);
                }
                ExceptionHelper.CheckReturnCode(BCryptGenRandom(IntPtr.Zero, pointer, spanToFill.Length, BCRYPT_USE_SYSTEM_PREFERRED_RNG));
            }
            finally
            {
                if (handle.IsAllocated)
                {
                    handle.Free();
                }
            }
        }
    }
}

