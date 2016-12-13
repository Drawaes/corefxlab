using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.KeyExchange
{
    public class KeyExchangeFactory
    {
        private ICertificate _certificate;

        public KeyExchangeFactory(ICertificate certificate)
        {
            _certificate = certificate;


        }
    }
}
