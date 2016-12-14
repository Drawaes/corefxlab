using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed
{
    internal static class BufferExtensions
    {
        internal static int ReadBigEndian24bit(this ReadableBuffer buffer)
        {
            uint contentSize = buffer.ReadBigEndian<ushort>();
            contentSize = (contentSize << 8) + buffer.Slice(2).ReadBigEndian<byte>();
            return (int)contentSize;
        }

        internal static void Write24BitNumber(int numberToWrite, Memory<byte> buffer)
        {
            buffer.Span.Write((byte)(((numberToWrite & 0xFF0000) >> 16)));
            buffer.Span.Slice(1).Write((byte)(((numberToWrite & 0x00ff00) >> 8)));
            buffer.Span.Slice(2).Write((byte)(numberToWrite & 0x0000ff));
        }

        internal static void Write16BitNumber(this Span<byte> span, ushort numberToWrite)
        {
            span.Write((byte)((numberToWrite & 0xFF00) >> 8));
            span = span.Slice(1);
            span.Write((byte)((numberToWrite & 0x00FF)));
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
