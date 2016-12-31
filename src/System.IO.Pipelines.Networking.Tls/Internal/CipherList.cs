using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Internal
{
    public class CipherList
    {
        private Dictionary<ushort, CipherSuite> _ciphers = new Dictionary<ushort, CipherSuite>();

        public CipherList()
        {
            _ciphers.Add(0x009C, new CipherSuite(0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256", TlsVersion.Tls12));
            _ciphers.Add(0x009D, new CipherSuite(0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384", TlsVersion.Tls12));
            _ciphers.Add(0xC02B, new CipherSuite(0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", TlsVersion.Tls12));
            _ciphers.Add(0xC02C, new CipherSuite(0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", TlsVersion.Tls12));
            _ciphers.Add(0xC02F, new CipherSuite(0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", TlsVersion.Tls12));
            _ciphers.Add(0xC030, new CipherSuite(0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", TlsVersion.Tls12));
            _ciphers.Add(0x1301, new CipherSuite(0x1301, "TLS_AES_128_GCM_SHA256", TlsVersion.Tls13, TlsVersion.Tls13Draft18));
            _ciphers.Add(0x1302, new CipherSuite(0x1302, "TLS_AES_256_GCM_SHA384", TlsVersion.Tls13, TlsVersion.Tls13Draft18));
            _ciphers.Add(0x1303, new CipherSuite(0x1303, "TLS_CHACHA20_POLY1305_SHA256", TlsVersion.Tls13, TlsVersion.Tls13Draft18));
            _ciphers.Add(0x1304, new CipherSuite(0x1304, "TLS_AES_128_CCM_SHA256", TlsVersion.Tls13, TlsVersion.Tls13Draft18));
            _ciphers.Add(0x1305, new CipherSuite(0x1305, "TLS_AES_128_CCM_8_SHA256", TlsVersion.Tls13, TlsVersion.Tls13Draft18));
        }

        public bool TryGetCipherSuite(ushort cipherCode, TlsVersion tlsVersion, out CipherSuite cipherSuite)
        {
            if(!_ciphers.TryGetValue(cipherCode, out cipherSuite))
            {
                return false;
            }
            return cipherSuite.IsSupported(tlsVersion);
        }
    }
}
