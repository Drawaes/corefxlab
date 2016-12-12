using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Internal.ManagedTls;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.KeyExchange
{
    public class EdhKeyExchange : IKeyExchangeProvider
    {
        private readonly KeyExchangeType _keyExchangeType;
        private readonly bool _isEphemeral;
        private IntPtr _key;
        private IntPtr _provider;
        private Dictionary<string, IntPtr> _providers = new Dictionary<string, IntPtr>();

        public EdhKeyExchange(KeyExchangeType exchangeType, IntPtr privateKey, bool isEphemeral)
        {
            IntPtr handle;
            Interop.BCryptOpenAlgorithmProvider(out handle, "ECDH", null, 0);
            _provider = handle;
            _keyExchangeType = exchangeType;
            _isEphemeral = isEphemeral;
            _key = privateKey;
        }

        public IntPtr GetProvider(string namedCurve)
        {
            lock (_providers)
            {
                IntPtr returnPtr;
                if (!_providers.TryGetValue(namedCurve, out returnPtr))
                {
                    Interop.CheckReturnOrThrow(Interop.BCryptOpenAlgorithmProvider(out returnPtr, "ECDH", null, 0));
                    InteropCurves.SetEccCurveName(returnPtr, namedCurve);
                    _providers.Add(namedCurve, returnPtr);
                }
                return returnPtr;
            }
        }

        public KeyExchangeType KeyExchangeType => _keyExchangeType;

        public IKeyExchangeInstance GetInstance(ManagedConnectionContext context)
        {
            if (_isEphemeral)
            {
                return new EDHEInstance(_key, context, this);
            }
            else
            {
                return new EDHInstance(_key, context);
            }
        }
    }
}
