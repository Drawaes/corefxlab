using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls
{
    public static class BufferExtensions
    {
        public static int ReadBigEndian24bit(this ReadableBuffer buffer)
        {
            uint contentSize = buffer.ReadBigEndian<ushort>();
            contentSize = (contentSize << 8) + buffer.Slice(2).ReadBigEndian<byte>();
            return (int)contentSize;
        }

        public static ReadableBuffer SliceVector<[Primitive]T>(ref ReadableBuffer buffer) where T :struct
        {
            uint length = 0;
            if (typeof(T) == typeof(byte) || typeof(T) == typeof(sbyte))
            {
                length = buffer.ReadBigEndian<byte>();
                buffer = buffer.Slice(sizeof(byte));
            }
            else if (typeof(T) == typeof(ushort) || typeof(T) == typeof(short))
            {
                length = buffer.ReadBigEndian<ushort>();
                buffer = buffer.Slice(sizeof(ushort));
            }
            else if (typeof(T) == typeof(uint) || typeof(T) == typeof(int))
            {
                length = buffer.ReadBigEndian<uint>();
                buffer = buffer.Slice(sizeof(uint));
            }
            else
            {
                Internal.ExceptionHelper.ThrowException(new InvalidCastException($"The type {typeof(T)} is not a primitave integer type"));
            }
            var returnBuffer = buffer.Slice(0,(int)length);
            buffer = buffer.Slice(returnBuffer.End);
            return returnBuffer;
        }
    }
}
