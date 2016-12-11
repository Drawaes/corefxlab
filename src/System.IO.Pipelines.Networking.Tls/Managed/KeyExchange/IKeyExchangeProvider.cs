using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.KeyExchange
{
    public interface IKeyExchangeProvider
    {
        KeyExchangeType KeyExchangeType {get;}
        IKeyExchangeInstance GetInstance(ManagedConnectionContext context);
    }
}
