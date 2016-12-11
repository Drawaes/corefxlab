using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.KeyExchange
{
    public class HeritageKeyExchange : IKeyExchangeProvider
    {
        private readonly KeyExchangeType _keyExchangeType;

        public HeritageKeyExchange(KeyExchangeType exchangeType)
        {
            _keyExchangeType = exchangeType;
        }
        public KeyExchangeType KeyExchangeType => _keyExchangeType;

        public IKeyExchangeInstance GetInstance(ManagedConnectionContext context)
        {
            throw new NotImplementedException();
        }

        public void SetBufferPool(NativeBufferPool nativeBuffer)
        {
        }

        public int Buffer
        {
            get
            {
                return 0;//Internal.ManagedTls.InteropProperties.GetObjectLength(_provider);
            }
        }
    }
}
