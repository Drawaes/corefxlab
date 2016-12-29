using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Unix;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.TlsSpec;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.KeyExchange.Unix
{
    internal class EcdhExchangeProvider : IKeyExchangeProvider
    {
        private ICertificate _certificate;
        private bool _isEphemeral;
        private static readonly string s_providerName = KeyExchangeType.ECDH.ToString();
        private int[] _curveNids;

        public EcdhExchangeProvider(ICertificate certificate, bool isEphemeral)
        {
            _isEphemeral = isEphemeral;
            _certificate = certificate;
            _curveNids = InteropCurves.GetCurveNids();
        }

        public ICertificate Certificate => _certificate;

        public void Dispose()
        {
            throw new NotImplementedException();
        }

        internal int GetNid(int curveId)
        {
            return _curveNids[curveId];
        }

        public IKeyExchangeInstance GetInstance(IConnectionState state)
        {
            if (_isEphemeral)
            {
                var instance = new EcdheExchangeInstance(state, this);
                instance.SetSignature(_certificate.GetHashandSignInstance(state.CipherSuite.Hash.HashType, PaddingType.Pkcs1), _certificate);
                return instance;
            }
            throw new NotImplementedException();
        }
    }
}
