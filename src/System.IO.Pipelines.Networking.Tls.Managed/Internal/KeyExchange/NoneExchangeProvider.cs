﻿using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.KeyExchange
{
    internal class NoneExchangeProvider : IKeyExchangeProvider
    {
        private ICertificate _certificate;

        public NoneExchangeProvider(ICertificate certificate)
        {
            _certificate = certificate;
        }

        public ICertificate Certificate => _certificate;
        
        public IKeyExchangeInstance GetInstance(IConnectionState state)
        {
            var instance = new NoneExchangeInstance(state);
            instance.SetSignature(null,_certificate);
            return instance;
        }

        public void Dispose()
        {
        }
    }
}
