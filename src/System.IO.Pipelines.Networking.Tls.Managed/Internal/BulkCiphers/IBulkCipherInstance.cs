using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.TlsSpec;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.BulkCiphers
{
    internal interface IBulkCipherInstance:IDisposable
    {
        byte[] HmacKey { set; }
        int TrailerSize { get; }
        int ExplicitNonceSize { get; }

        void SetNonce(Span<byte> nounce);
        void DecryptFrame(ReadableBuffer buffer, ref WritableBuffer writer);
        void WriteExplicitNonce(ref WritableBuffer buffer);
        void Encrypt(ref WritableBuffer buffer, ReadableBuffer plainText, TlsFrameType frameType, IConnectionState state);
    }
}
