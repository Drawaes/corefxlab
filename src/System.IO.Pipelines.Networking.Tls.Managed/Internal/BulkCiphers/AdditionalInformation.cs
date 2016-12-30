using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.BulkCiphers
{
    [StructLayout(LayoutKind.Sequential,Pack =1)]
    internal struct AdditionalInformation
    {
        public ulong SequenceNumber;
        public byte FrameType;
        public ushort TlsVersion;
        public ushort ContentLength;

        public AdditionalInformation(ulong sequenceNumber, ushort contentLength, TlsSpec.TlsFrameType frameType)
        {
            SequenceNumber = BufferExtensions.Reverse(sequenceNumber);
            TlsVersion = TlsSpec.Tls12Utils.TLS_VERSION;
            FrameType = (byte) frameType;
            ContentLength = BufferExtensions.Reverse(contentLength);
        }

        
    }
}
