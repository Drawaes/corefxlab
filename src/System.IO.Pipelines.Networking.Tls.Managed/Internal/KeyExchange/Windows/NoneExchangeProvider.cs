using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.KeyExchange.Windows
{
    internal class NoneExchangeProvider : IKeyExchangeProvider
    {
        private ICertificate _certificate;

        public NoneExchangeProvider(ICertificate certificate)
        {
            _certificate = certificate;
        }

        public ICertificate Certificate => _certificate;
        
        public IKeyExchangeInstance GetInstance(ConnectionState state)
        {
            return new NoneExchangeInstance(_certificate,state);
        }

        public void Dispose()
        {
        }
    }
}
