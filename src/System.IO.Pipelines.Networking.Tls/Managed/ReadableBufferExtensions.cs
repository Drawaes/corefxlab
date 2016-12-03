using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed
{
    public static class ReadableBufferExtensions
    {
        public static int ReadBigEndian24bit(this ReadableBuffer buffer)
        {
            uint contentSize = buffer.ReadBigEndian<ushort>();
            buffer = buffer.Slice(2);
            contentSize = (contentSize << 8) + buffer.ReadBigEndian<byte>();
            return (int)contentSize;
        }
    }
}
