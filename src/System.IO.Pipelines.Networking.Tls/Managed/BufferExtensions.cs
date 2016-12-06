using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed
{
    public static class BufferExtensions
    {
        internal static int ReadBigEndian24bit(this ReadableBuffer buffer)
        {
            uint contentSize = buffer.ReadBigEndian<ushort>();
            buffer = buffer.Slice(2);
            contentSize = (contentSize << 8) + buffer.ReadBigEndian<byte>();
            return (int)contentSize;
        }

        internal static void Write24BitNumber(int numberToWrite, Memory<byte> buffer)
        {
            buffer.Span.Write((byte)(((numberToWrite & 0xFF0000) >> 16)));
            buffer.Span.Slice(1).Write((byte)(((numberToWrite & 0x00ff00) >> 8)));
            buffer.Span.Slice(2).Write((byte)(numberToWrite & 0x0000ff));
        }
        internal static void Write24BitNumber(int numberToWrite, ref WritableBuffer buffer)
        {
            buffer.Ensure(3);
            buffer.WriteBigEndian((byte)(((numberToWrite & 0xFF0000) >> 16)));
            buffer.WriteBigEndian((byte)(((numberToWrite & 0x00ff00) >> 8)));
            buffer.WriteBigEndian((byte)(numberToWrite & 0x0000ff));
        }
        internal static void Write64BitNumber(this Span<byte> span, ulong numberToWrite)
        {
            span.Write((byte)((numberToWrite & 0xFF00000000000000) >> 56));
            span = span.Slice(1);
            span.Write((byte)((numberToWrite & 0x00FF000000000000) >> 48));
            span = span.Slice(1);
            span.Write((byte)((numberToWrite & 0x0000FF0000000000) >> 40));
            span = span.Slice(1);
            span.Write((byte)((numberToWrite & 0x000000FF00000000) >> 32));
            span = span.Slice(1);
            span.Write((byte)((numberToWrite & 0x00000000FF000000) >> 24));
            span = span.Slice(1);
            span.Write((byte)((numberToWrite & 0x0000000000FF0000) >> 16));
            span = span.Slice(1);
            span.Write((byte)((numberToWrite & 0x000000000000FF00) >> 8));
            span = span.Slice(1);
            span.Write((byte)((numberToWrite & 0x00000000000000FF)));
        }
        internal static void Write16BitNumber(this Span<byte> span, ushort numberToWrite)
        {
            span.Write((byte)((numberToWrite & 0xFF00) >> 8));
            span = span.Slice(1);
            span.Write((byte)((numberToWrite & 0x00FF)));
        }
    }
}
