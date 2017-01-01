using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.KeyExchange.OpenSsl11
{
    public class EcdheKeyExchangeInstance : IKeyExchangeInstance
    {
        private int _nid;
        private bool _processedClientKey;
        private NamedGroup _namedGroup;

        internal EcdheKeyExchangeInstance(int nid, NamedGroup namedGroup)
        {
            _nid = nid;
            _namedGroup = namedGroup;
        }

        public bool HasClientKey => _processedClientKey;
        public NamedGroup NamedGroup => _namedGroup;

        public unsafe void SetClientKey(ReadableBuffer buffer)
        {
            GCHandle handle;
            void* ptr;
            if(buffer.IsSingleSpan)
            {
                ptr = buffer.First.GetPointer(out handle);
            }
            else
            {
                var tmpBuffer = stackalloc byte[buffer.Length];
                var span = new Span<byte>(tmpBuffer,buffer.Length);
                buffer.CopyTo(span);
                ptr = tmpBuffer;
            }
            throw new NotImplementedException();
        }
    }
}
