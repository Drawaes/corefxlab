using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.KeyExchange
{
    public class KeyExchangeFactory
    {
        private static readonly int s_maxEnumValue = Enum.GetValues(typeof(KeyExchangeType)).Cast<byte>().Max();
        private readonly IKeyExchangeProvider[] _providers = new IKeyExchangeProvider[s_maxEnumValue + 1];
        
        public KeyExchangeFactory(IntPtr privateKey)
        {
            var keyAlgo = Internal.ManagedTls.InteropCertificates.GetPrivateKeyAlgo(privateKey);
            var privateKeyType = (KeyExchangeType)Enum.Parse(typeof(KeyExchangeType), keyAlgo, true);

            switch (privateKeyType)
            {
                //case KeyExchangeType.ECDH:
                //    SetupEcdsaExchanges(privateKey);
                //    break;
                case KeyExchangeType.RSA:
                    SetupRsaExchanges(privateKey);
                    break;
                default:
                    throw new InvalidOperationException($"Unsupported key type {privateKeyType}");
            }
        }

        private void SetupRsaExchanges(IntPtr keyHandle)
        {
            foreach (var v in Enum.GetNames(typeof(KeyExchangeType)))
            {
                var t = (KeyExchangeType)Enum.Parse(typeof(KeyExchangeType), v);

                if (v.Contains("RSA"))
                {
                    if (v.StartsWith("ECDHE", StringComparison.OrdinalIgnoreCase))
                    {
                        //Eliptic curve diffe hellman
                        var keyExchange = new EdhKeyExchange(t, keyHandle, true);
                        _providers[(int)t] = keyExchange;
                    }
                    else if (v.StartsWith("DHE", StringComparison.OrdinalIgnoreCase))
                    {
                        var keyExchange = new DHKeyExchange(t, keyHandle, true);
                        _providers[(int)t] = keyExchange;
                    }
                    else if (v.Length == 3)
                    {
                        var keyExchange = new HeritageKeyExchange(t);
                        _providers[(int)t] = keyExchange;
                    }

                }
            }
        }

        private void SetupEcdsaExchanges(IntPtr keyHandle)
        {
            foreach(var v in Enum.GetNames(typeof(KeyExchangeType)))
            {
                if(v.EndsWith("ECDSA",StringComparison.OrdinalIgnoreCase))
                {
                    if(v.StartsWith("ECDH",StringComparison.OrdinalIgnoreCase))
                    {
                        var t = (KeyExchangeType)Enum.Parse(typeof(KeyExchangeType), v);
                        //Eliptic curve diffe hellman
                        var keyExchange = new EdhKeyExchange(t, keyHandle, v[5] == 'E');
                        _providers[(int)t] = keyExchange;
                    }
                }
            }
        }

        internal IKeyExchangeProvider GetKeyProvider(KeyExchangeType keyExchangeType)
        {
            var value = (int)keyExchangeType;
            if(value < 0 || value > s_maxEnumValue)
            {
                throw new ArgumentOutOfRangeException(nameof(keyExchangeType));
            }
            return _providers[value];
        }
    }
}
