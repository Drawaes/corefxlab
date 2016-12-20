using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.TlsSpec;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.BulkCiphers.Windows
{
    internal class HmacCipherKey : IBulkCipherInstance
    {
        public int ExplicitNonceSize
        {
            get
            {
                throw new NotImplementedException();
            }
        }

        public byte[] HmacKey
        {
            set
            {
                throw new NotImplementedException();
            }
        }

        public int TrailerSize
        {
            get
            {
                throw new NotImplementedException();
            }
        }

        public void DecryptFrame(ReadableBuffer buffer, ref WritableBuffer writer)
        {
            throw new NotImplementedException();
        }

        public void Dispose()
        {
            throw new NotImplementedException();
        }

        public void Encrypt(ref WritableBuffer buffer, ReadableBuffer plainText, TlsFrameType frameType, ConnectionState state)
        {
            throw new NotImplementedException();
        }

        public void SetNonce(Span<byte> nounce)
        {
            throw new NotImplementedException();
        }

        public void WriteExplicitNonce(ref WritableBuffer buffer)
        {
            throw new NotImplementedException();
        }
    }
}
