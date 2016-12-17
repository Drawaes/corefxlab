using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.KeyExchange
{
    public interface IKeyExchangeInstance:IDisposable
    {
        void ProcessSupportedGroupsExtension(ReadableBuffer buffer);
        void ProcessEcPointFormats(ReadableBuffer buffer);
        void WriteServerKeyExchange(ref WritableBuffer buffer);
        byte[] ProcessClientKeyExchange(ReadableBuffer buffer);
    }
}
