using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.KeyExchange
{
    internal interface IKeyExchangeProvider : IDisposable
    {
        IKeyExchangeInstance GetInstance(ConnectionState state);
        ICertificate Certificate { get;}
    }
}
