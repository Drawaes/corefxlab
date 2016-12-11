using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.KeyExchange
{
    public class DHKeyExchange : IKeyExchangeProvider
    {
        private readonly KeyExchangeType _keyExchangeType;
        private readonly bool _isEphemeral;
        private IntPtr _key;
        private IntPtr _provider;
        
        public DHKeyExchange(KeyExchangeType exchangeType, IntPtr privateKey, bool isEphemeral)
        {
            var algo = "DH";
            IntPtr handle;
            Internal.ManagedTls.Interop.BCryptOpenAlgorithmProvider(out handle, algo, null, 0);
            _provider = handle;
            _keyExchangeType = exchangeType;
            _key = privateKey;
            _isEphemeral = isEphemeral;
        }

        public KeyExchangeType KeyExchangeType => _keyExchangeType;

        public IKeyExchangeInstance GetInstance(ManagedConnectionContext context)
        {
            if (_isEphemeral)
            {
                return new DHEInstance(_key, context, _provider);
            }
            throw new NotImplementedException();
        }
    }
}
