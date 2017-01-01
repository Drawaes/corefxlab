using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.KeyExchange
{
    public interface IKeyExchangeProvider
    {
        IKeyExchangeInstance GetInstance(NamedGroup group);
        IKeyExchangeInstance GetInstance(NamedGroup group, ReadableBuffer keyData);
    }
}
