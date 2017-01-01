using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.KeyExchange
{
    public interface IKeyExchangeInstance
    {
        bool HasClientKey { get;}
        void SetClientKey(ReadableBuffer buffer);
        NamedGroup NamedGroup { get;}
    }
}
