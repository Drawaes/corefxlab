using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.KeyExchange
{
    internal class KeyExchangeFactory
    {
        private ICertificate _certificate;
        private EcdhExchangeProvider _ecdheProvider;

        public KeyExchangeFactory(ICertificate certificate)
        {
            _certificate = certificate;
        }

        public IKeyExchangeProvider GetKeyExchange(string keyExchange)
        {
            var keyAndSigSplit = keyExchange.Split('_');
            var certMode = (CertificateType) Enum.Parse(typeof(CertificateType), keyAndSigSplit[keyAndSigSplit.Length -1],true);
            var exchangeMode = keyAndSigSplit.Length == 1 ? KeyExchangeType.None : (KeyExchangeType) Enum.Parse(typeof(KeyExchangeType),keyAndSigSplit[0],true);

            if(_certificate.CertificateType != certMode)
            {
                return null;
            }
            switch(exchangeMode)
            {
                case KeyExchangeType.ECDHE:
                    if (_ecdheProvider == null)
                    {
                        _ecdheProvider = new EcdhExchangeProvider(_certificate,true);
                    }
                    return _ecdheProvider;
                case KeyExchangeType.None:
                    return null;
                default:
                    return null;
            }
        }
    }
}
