using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Windows
{
    public static class InteropRandom
    {
        public unsafe static void GetRandom(Memory<byte> spanToFill)
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
                ExceptionHelper.CheckReturnCode(global::Interop.BCrypt.BCryptGenRandom((byte*)pointer, spanToFill.Length));
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

