using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.BulkCiphers;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.BulkCiphers.Unix;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.BulkCiphers.Windows;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash.Unix;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash.Windows;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.KeyExchange;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.KeyExchange.Unix;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.KeyExchange.Windows;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.TlsSpec;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal
{
    internal class CipherList
    {
        private readonly CipherSuite[][] _suites = new CipherSuite[256][];
        private readonly IBulkCipherPal _bulkFactory;
        private readonly IHashPal _hashFactory;
        private readonly IKeyExchangePal _keyFactory;
        private readonly ICertificatePal _certificateFactory;
        private const int BUFFER_POOL_COUNT = 500;

        public CipherList(ICertificatePal certificateFactory)
        {
            _certificateFactory = certificateFactory;
            _certificateFactory.SetCipherList(this);
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                _hashFactory = new UnixHashPal();
                //_hashFactory = new WindowsHashPal();
                //_keyFactory = new WindowsKeyExchangePal();
                _keyFactory = new UnixKeyExchangePal();
                _bulkFactory = new WindowsBulkCipherPal();
                //_bulkFactory = new UnixBulkCipherPal();
            }
            else
            {
                throw new NotImplementedException("OPEN SSL is yet to come");
            }
            _keyFactory.SetCertificatePal(_certificateFactory);
            
            SetList();        
            CleanUpList();

            _hashFactory.FinishSetup(BUFFER_POOL_COUNT);
            _bulkFactory.FinishSetup(BUFFER_POOL_COUNT);
        }

        public ICertificatePal CertificateFactory => _certificateFactory;
        public IHashPal HashFactory => _hashFactory;
        public IKeyExchangePal KeyFactory => _keyFactory;

        private void CleanUpList()
        {
            for(var i = 0; i < _suites.Length;i++)
            {
                var suite = _suites[i];
                if(suite != null)
                {
                    for(var s = 0; s < suite.Length;s ++)
                    {
                        if(suite[s]?.IsValid() != true)
                        {
                            suite[s] = null;
                        }
                    }
                }
            }
        }

        private void SetList()
        {
            var list = new Dictionary<ushort,string>();
            list.Add(0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA");
            list.Add(0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA");
            list.Add(0x003C, "TLS_RSA_WITH_AES_128_CBC_SHA256");
            list.Add(0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256");
            list.Add(0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256");
            list.Add(0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384");
            list.Add(0xC008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA");
            list.Add(0xC009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA");
            list.Add(0xC00A, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA");
            list.Add(0xC00D, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA");
            list.Add(0xC012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA");
            list.Add(0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
            list.Add(0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA");
            list.Add(0xC023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256");
            list.Add(0xC024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384");
            list.Add(0xC027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256");
            list.Add(0xC028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384");
            list.Add(0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
            list.Add(0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
            list.Add(0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
            list.Add(0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
            list.Add(0x1301, "TLS_AES_128_GCM_SHA256");
            list.Add(0x1302, "TLS_AES_256_GCM_SHA384");
            list.Add(0x1303, "TLS_CHACHA20_POLY1305_SHA256"); 
            list.Add(0x1304, "TLS_AES_128_CCM_SHA256");
            list.Add(0x1305, "TLS_AES_128_CCM_8_SHA256");

            foreach (var kv in list)
            {
                var cs = new CipherSuite(kv.Key,kv.Value, _bulkFactory,_hashFactory,_keyFactory);
                if(cs.IsValid())
                {
                    int firstByte = ((byte)(kv.Key >> 8));
                    int secondByte = ((byte)kv.Key);
                    if(_suites[firstByte] == null)
                    {
                        _suites[firstByte] = new CipherSuite[256];
                    }
                    _suites[firstByte][secondByte] = cs;
                }
            }
        }

        public CipherSuite GetCipherInfo(ushort cipherKey)
        {
            var frontKey = cipherKey >> 8;
            if(_suites[frontKey] != null)
            {
                var suite = _suites[frontKey];
                return suite[(byte)cipherKey];
            }
            return null;
        }
    }
}
