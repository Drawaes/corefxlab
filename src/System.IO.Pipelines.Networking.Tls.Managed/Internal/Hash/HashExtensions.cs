using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed
{
    internal static class HashExtensions
    {
        public static unsafe void HashData(this IHashInstance hash, Memory<byte> memory)
        {
            void* pointer;
            if (!memory.TryGetPointer(out pointer))
            {
                ArraySegment<byte> arrayBuffer;
                memory.TryGetArray(out arrayBuffer);
                fixed (byte* arrayPtr = arrayBuffer.Array)
                {
                    var frontPtr = arrayPtr + arrayBuffer.Offset;
                    hash.HashData(arrayPtr, memory.Length);
                }
            }
            else
            {
                hash.HashData((byte*)pointer, memory.Length);
            }
        }

        public static void HashData(this IHashInstance hash, ReadableBuffer buffer)
        {
            foreach (var memory in buffer)
            {
                hash.HashData(memory);
            }
        }
    }
}
