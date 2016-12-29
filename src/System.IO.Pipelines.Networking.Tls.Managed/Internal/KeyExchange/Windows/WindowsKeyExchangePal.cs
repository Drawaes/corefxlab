using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.KeyExchange.Windows
{
    internal class WindowsKeyExchangePal : IKeyExchangePal
    {
        private static readonly int s_NumberOfKeyExchangeTypes = ((int[])Enum.GetValues(typeof(KeyExchangeType))).Max() + 1;
        //Not going to bother to support others
        private IKeyExchangeProvider[] _rsa = new IKeyExchangeProvider[s_NumberOfKeyExchangeTypes];
        private IKeyExchangeProvider[] _ecdsa = new IKeyExchangeProvider[s_NumberOfKeyExchangeTypes];
        private ICertificatePal _certFactory;
        private EcdhExchangeProvider _ecdhProvider;

        public WindowsKeyExchangePal()
        {
            _ecdhProvider = new EcdhExchangeProvider(null, true);
        }

        public IKeyExchangeProvider GetKeyExchange(string keyExchange)
        {
            var keyAndSigSplit = keyExchange.Split('_');
            var certMode = (CertificateType)Enum.Parse(typeof(CertificateType), keyAndSigSplit[keyAndSigSplit.Length - 1], true);
            var exchangeMode = keyAndSigSplit.Length == 1 ? KeyExchangeType.None : (KeyExchangeType)Enum.Parse(typeof(KeyExchangeType), keyAndSigSplit[0], true);

            ICertificate certificate = _certFactory.TryGetCertificate(certMode);
            if (certificate == null)
            {
                return null;
            }
            else if (certificate.CertificateType == CertificateType.Rsa)
            {
                IKeyExchangeProvider prov = _rsa[(int)exchangeMode];
                if (prov == null)
                {
                    switch (exchangeMode)
                    {
                        case KeyExchangeType.None:
                            prov = new NoneExchangeProvider(certificate);
                            _rsa[(int)exchangeMode] = prov;
                            return prov;
                        case KeyExchangeType.ECDHE:
                            prov = new EcdhExchangeProvider(certificate, true);
                            _rsa[(int)exchangeMode] = prov;
                            return prov;
                    }
                }
                return prov;
            }
            else if (certificate.CertificateType == CertificateType.Ecdsa)
            {

            }
            return null;
        }

        public void SetCertificatePal(ICertificatePal certificateFactory)
        {
            _certFactory = certificateFactory;
        }

        public ITls13KeyExchangeInstance GetKeyExchangeInstance(NamedGroup group)
        {
            if(((ushort)group & 0xff00) == 0)
            {
                //ECDHE
                TlsSpec.EllipticCurves ec;
                if (Enum.TryParse(group.ToString(), true, out ec))
                {
                    var prov = _ecdhProvider.GetProvider(ec);
                    if(prov != null)
                    {
                        throw new NotImplementedException("Matched a curve need to make the instance now");
                    }
                }
            }
            return null;
        }
    }
}
