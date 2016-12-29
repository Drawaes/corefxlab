using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.KeyExchange
{
    internal interface IKeyExchangePal
    {
        void SetCertificatePal(ICertificatePal certificateFactory);
        IKeyExchangeProvider GetKeyExchange(string keyExchange);
        ITls13KeyExchangeInstance GetKeyExchangeInstance(NamedGroup group);
    }
}
