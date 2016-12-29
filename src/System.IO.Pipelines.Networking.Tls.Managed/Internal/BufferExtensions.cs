using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal
{
    internal static class BufferExtensions
    {
        internal static int ReadBigEndian24bit(this ReadableBuffer buffer)
        {
            uint contentSize = buffer.ReadBigEndian<ushort>();
            contentSize = (contentSize << 8) + buffer.Slice(2).ReadBigEndian<byte>();
            return (int)contentSize;
        }

        internal static ulong Reverse(ulong value)
        {
            value = (value << 32) | (value >> 32);
            value = ((value & 0xFFFF0000FFFF0000) >> 16) | ((value & 0x0000FFFF0000FFFF) << 16);
            value = ((value & 0xFF00FF00FF00FF00) >> 8) | ((value & 0x00FF00FF00FF00FF) << 8);
            return value;
        }

        internal static uint Reverse(uint value)
        {
            value = ((value & 0xFFFF0000) >> 16) | ((value & 0x0000FFFF) << 16);
            value = ((value & 0xFF00FF00) >> 8) | ((value & 0x00FF00FF) << 8);
            return value;
        }

        internal static ushort Reverse(ushort value)
        {
            value = (ushort)((value >> 8) | (value << 8));
            return value;
        }

        internal static Span<byte> Write64BitBigEndian(this Span<byte> span, ulong value)
        {
            value = Reverse(value);
            span.Write(value);
            return span.Slice(sizeof(ulong));
        }

        internal static void Write24BitNumber(int numberToWrite, Memory<byte> buffer)
        {
            buffer.Span.Write((byte)(((numberToWrite & 0xFF0000) >> 16)));
            buffer.Span.Slice(1).Write((byte)(((numberToWrite & 0x00ff00) >> 8)));
            buffer.Span.Slice(2).Write((byte)(numberToWrite & 0x0000ff));
        }

        internal static Span<byte> Write16BitNumber(this Span<byte> span, ushort value)
        {
            value = Reverse(value);
            span.Write(value);
            return span.Slice(sizeof(ushort));
        }

        internal static void Write24BitNumber(int numberToWrite, ref WritableBuffer buffer)
        {
            buffer.Ensure(3);
            buffer.WriteBigEndian((byte)(((numberToWrite & 0xFF0000) >> 16)));
            buffer.WriteBigEndian((byte)(((numberToWrite & 0x00ff00) >> 8)));
            buffer.WriteBigEndian((byte)(numberToWrite & 0x0000ff));
        }
    }
}
