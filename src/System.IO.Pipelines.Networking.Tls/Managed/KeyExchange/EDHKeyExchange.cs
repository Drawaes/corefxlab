using System;
using System.Buffers;
using System.Collections.Generic;
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

        public EdhKeyExchange(KeyExchangeType exchangeType, IntPtr privateKey, bool isEphemeral)
        {
            var algos = Internal.ManagedTls.Interop.SecretAlgorithms.First(s => s.pszName == "ECDSA_P256").pszName;
            IntPtr handle;
            Internal.ManagedTls.Interop.BCryptOpenAlgorithmProvider(out handle, algos, null,0);
            _provider = handle;
            _keyExchangeType = exchangeType;
            _isEphemeral = isEphemeral;
        }

        public KeyExchangeType KeyExchangeType => _keyExchangeType;

        public int Buffer
        {
            get
            {
                return Internal.ManagedTls.InteropProperties.GetObjectLength(_provider);
            }
        }

        public IKeyExchangeInstance GetInstance(ManagedConnectionContext context)
        {
            if (_isEphemeral)
            {
                return new EDHEInstance(_key, context,_provider);
            }
            else
            {
                return new EDHInstance(_key, context);
            }
        }

        public void SetBufferPool(NativeBufferPool nativeBuffer)
        {
            
        }
    }
}
