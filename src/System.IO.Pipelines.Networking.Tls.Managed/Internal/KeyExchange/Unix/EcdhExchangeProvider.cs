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

        public IKeyExchangeInstance GetInstance(ConnectionState state)
        {
            if (_isEphemeral)
            {
                return new EcdheExchangeInstance(_certificate, state, this);
            }
            throw new NotImplementedException();
        }
    }
}
