﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
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

        public static Span<byte> Write64BitBigEndian(this Span<byte> span, ulong value)
        {
            value = Reverse(value);
            span.Write(value);
            return span.Slice(sizeof(ulong));
        }

        public static void Write24BitNumber(int numberToWrite, Memory<byte> buffer)
        {
            buffer.Span.Write((byte)(((numberToWrite & 0xFF0000) >> 16)));
            buffer.Span.Slice(1).Write((byte)(((numberToWrite & 0x00ff00) >> 8)));
            buffer.Span.Slice(2).Write((byte)(numberToWrite & 0x0000ff));
        }

        public static Span<byte> Write16BitNumber(this Span<byte> span, ushort value)
        {
            value = Reverse(value);
            span.Write(value);
            return span.Slice(sizeof(ushort));
        }

        public static unsafe void* GetPointer(this Memory<byte> buffer, out GCHandle handle)
        {
            void* ptr;
            if(buffer.TryGetPointer(out ptr))
            {
                handle = default(GCHandle);
                return ptr;
            }
            ArraySegment<byte> array;
            buffer.TryGetArray(out array);
            handle = GCHandle.Alloc(array, GCHandleType.Pinned);
            ptr =(void*) IntPtr.Add(handle.AddrOfPinnedObject(),array.Offset);
            return ptr;
        }

        public static ReadableBuffer ReadAndSliceBigEndian<[Primitive] T>(this ReadableBuffer buffer, out T value) where T : struct
        {
            value = buffer.ReadBigEndian<T>();
            return buffer.Slice(Unsafe.SizeOf<T>());
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

        private static ushort Reverse(ushort value)
        {
            value = (ushort)((value >> 8) | (value << 8));
            return value;
        }

        private static ulong Reverse(ulong value)
        {
            value = (value << 32) | (value >> 32);
            value = ((value & 0xFFFF0000FFFF0000) >> 16) | ((value & 0x0000FFFF0000FFFF) << 16);
            value = ((value & 0xFF00FF00FF00FF00) >> 8) | ((value & 0x00FF00FF00FF00FF) << 8);
            return value;
        }

        private static uint Reverse(uint value)
        {
            value = ((value & 0xFFFF0000) >> 16) | ((value & 0x0000FFFF) << 16);
            value = ((value & 0xFF00FF00) >> 8) | ((value & 0x00FF00FF) << 8);
            return value;
        }
    }
}
