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
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal
{
    internal class CipherList
    {
        private readonly CipherSuite[] _00ciphers = new CipherSuite[255 + 1];
        private readonly CipherSuite[] _C0ciphers = new CipherSuite[255 + 1];
        private readonly IBulkCipherPal _bulkFactory;
        private readonly IHashPal _hashFactory;
        private readonly IKeyExchangePal _keyFactory;
        private readonly ICertificatePal _certificateFactory;
        private const int BUFFER_POOL_COUNT = 500;

        public CipherList(ICertificatePal certificateFactory)
        {
            _certificateFactory = certificateFactory;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                _hashFactory = new UnixHashPal();
                //_hashFactory = new WindowsHashPal();
                //_keyFactory = new WindowsKeyExchangePal();
                _keyFactory = new UnixKeyExchangePal();
                //_bulkFactory = new WindowsBulkCipherPal();
                _bulkFactory = new UnixBulkCipherPal();
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

        private void CleanUpList()
        {
            for (int i = 0; i < _C0ciphers.Length; i++)
            {
                if (_C0ciphers[i]?.IsValid() != true)
                {
                    _C0ciphers[i] = null;
                }
                if (_00ciphers[i]?.IsValid() != true)
                {
                    _00ciphers[i] = null;
                }
            }
        }

        private void SetList()
        {
            _00ciphers[0x0A] = new CipherSuite(0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0x0D] = new CipherSuite(0x000D, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0x10] = new CipherSuite(0x0010, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0x13] = new CipherSuite(0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0x16] = new CipherSuite(0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            _00ciphers[0x2F] = new CipherSuite(0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0x30] = new CipherSuite(0x0030, "TLS_DH_DSS_WITH_AES_128_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0x31] = new CipherSuite(0x0031, "TLS_DH_RSA_WITH_AES_128_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0x32] = new CipherSuite(0x0032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0x33] = new CipherSuite(0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            _00ciphers[0x35] = new CipherSuite(0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0x36] = new CipherSuite(0x0036, "TLS_DH_DSS_WITH_AES_256_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0x37] = new CipherSuite(0x0037, "TLS_DH_RSA_WITH_AES_256_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0x38] = new CipherSuite(0x0038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0x39] = new CipherSuite(0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            _00ciphers[0x3C] = new CipherSuite(0x003C, "TLS_RSA_WITH_AES_128_CBC_SHA256", _bulkFactory, _hashFactory, _keyFactory);
            _00ciphers[0x3D] = new CipherSuite(0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0x3E] = new CipherSuite(0x003E, "TLS_DH_DSS_WITH_AES_128_CBC_SHA256", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0x3F] = new CipherSuite(0x003F, "TLS_DH_RSA_WITH_AES_128_CBC_SHA256", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0x40] = new CipherSuite(0x0040, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0x4A] = new CipherSuite(0x004A, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0x4B] = new CipherSuite(0x004B, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0x4C] = new CipherSuite(0x004C, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0x67] = new CipherSuite(0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0x68] = new CipherSuite(0x0068, "TLS_DH_DSS_WITH_AES_256_CBC_SHA256", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0x69] = new CipherSuite(0x0069, "TLS_DH_RSA_WITH_AES_256_CBC_SHA256", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0x6A] = new CipherSuite(0x006A, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0x6B] = new CipherSuite(0x006B, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0x8B] = new CipherSuite(0x008B, "TLS_PSK_WITH_3DES_EDE_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0x8C] = new CipherSuite(0x008C, "TLS_PSK_WITH_AES_128_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0x8D] = new CipherSuite(0x008D, "TLS_PSK_WITH_AES_256_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0x8F] = new CipherSuite(0x008F, "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0x90] = new CipherSuite(0x0090, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0x91] = new CipherSuite(0x0091, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0x93] = new CipherSuite(0x0093, "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0x94] = new CipherSuite(0x0094, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0x95] = new CipherSuite(0x0095, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            _00ciphers[0x9C] = new CipherSuite(0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256", _bulkFactory, _hashFactory, _keyFactory);
            _00ciphers[0x9D] = new CipherSuite(0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0x9E] = new CipherSuite(0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0x9F] = new CipherSuite(0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0xA0] = new CipherSuite(0x00A0, "TLS_DH_RSA_WITH_AES_128_GCM_SHA256", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0xA1] = new CipherSuite(0x00A1, "TLS_DH_RSA_WITH_AES_256_GCM_SHA384", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0xA2] = new CipherSuite(0x00A2, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0xA3] = new CipherSuite(0x00A3, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0xA4] = new CipherSuite(0x00A4, "TLS_DH_DSS_WITH_AES_128_GCM_SHA256", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0xA5] = new CipherSuite(0x00A5, "TLS_DH_DSS_WITH_AES_256_GCM_SHA384", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0xA8] = new CipherSuite(0x00A8, "TLS_PSK_WITH_AES_128_GCM_SHA256", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0xA9] = new CipherSuite(0x00A9, "TLS_PSK_WITH_AES_256_GCM_SHA384", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0xAA] = new CipherSuite(0x00AA, "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0xAB] = new CipherSuite(0x00AB, "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0xAC] = new CipherSuite(0x00AC, "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0xAD] = new CipherSuite(0x00AD, "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0xAE] = new CipherSuite(0x00AE, "TLS_PSK_WITH_AES_128_CBC_SHA256", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0xAF] = new CipherSuite(0x00AF, "TLS_PSK_WITH_AES_256_CBC_SHA384", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0xB2] = new CipherSuite(0x00B2, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0xB3] = new CipherSuite(0x00B3, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0xB6] = new CipherSuite(0x00B6, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256", _bulkFactory, _hashFactory, _keyFactory);
            //_00ciphers[0xB7] = new CipherSuite(0x00B7, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384", _bulkFactory, _hashFactory, _keyFactory);
            //_C0ciphers[0x03] = new CipherSuite(0xC003, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            //_C0ciphers[0x04] = new CipherSuite(0xC004, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            //_C0ciphers[0x05] = new CipherSuite(0xC005, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            _C0ciphers[0x08] = new CipherSuite(0xC008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            _C0ciphers[0x09] = new CipherSuite(0xC009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            _C0ciphers[0x0A] = new CipherSuite(0xC00A, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            _C0ciphers[0x0D] = new CipherSuite(0xC00D, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            //_C0ciphers[0x0E] = new CipherSuite(0xC00E, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            //_C0ciphers[0x0F] = new CipherSuite(0xC00F, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            _C0ciphers[0x12] = new CipherSuite(0xC012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            _C0ciphers[0x13] = new CipherSuite(0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            _C0ciphers[0x14] = new CipherSuite(0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            _C0ciphers[0x23] = new CipherSuite(0xC023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", _bulkFactory, _hashFactory, _keyFactory);
            _C0ciphers[0x24] = new CipherSuite(0xC024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", _bulkFactory, _hashFactory, _keyFactory);
            //_C0ciphers[0x25] = new CipherSuite(0xC025, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", _bulkFactory, _hashFactory, _keyFactory);
            //_C0ciphers[0x26] = new CipherSuite(0xC026, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384", _bulkFactory, _hashFactory, _keyFactory);
            _C0ciphers[0x27] = new CipherSuite(0xC027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", _bulkFactory, _hashFactory, _keyFactory);
            _C0ciphers[0x28] = new CipherSuite(0xC028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", _bulkFactory, _hashFactory, _keyFactory);
            //_C0ciphers[0x29] = new CipherSuite(0xC029, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", _bulkFactory, _hashFactory, _keyFactory);
            //_C0ciphers[0x2A] = new CipherSuite(0xC02A, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384", _bulkFactory, _hashFactory, _keyFactory);
            _C0ciphers[0x2B] = new CipherSuite(0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", _bulkFactory, _hashFactory, _keyFactory);
            _C0ciphers[0x2C] = new CipherSuite(0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", _bulkFactory, _hashFactory, _keyFactory);
            //_C0ciphers[0x2D] = new CipherSuite(0xC02D, "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", _bulkFactory, _hashFactory, _keyFactory);
            //_C0ciphers[0x2E] = new CipherSuite(0xC02E, "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384", _bulkFactory, _hashFactory, _keyFactory);
            _C0ciphers[0x2F] = new CipherSuite(0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", _bulkFactory, _hashFactory, _keyFactory);
            _C0ciphers[0x30] = new CipherSuite(0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", _bulkFactory, _hashFactory, _keyFactory);
            //_C0ciphers[0x31] = new CipherSuite(0xC031, "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", _bulkFactory, _hashFactory, _keyFactory);
            //_C0ciphers[0x32] = new CipherSuite(0xC032, "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384", _bulkFactory, _hashFactory, _keyFactory);
            //_C0ciphers[0x34] = new CipherSuite(0xC034, "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            //_C0ciphers[0x35] = new CipherSuite(0xC035, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            //_C0ciphers[0x36] = new CipherSuite(0xC036, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA", _bulkFactory, _hashFactory, _keyFactory);
            //_C0ciphers[0x37] = new CipherSuite(0xC037, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256", _bulkFactory, _hashFactory, _keyFactory);
            //_C0ciphers[0x38] = new CipherSuite(0xC038, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384", _bulkFactory, _hashFactory, _keyFactory);
        }

        public CipherSuite GetCipherInfo(ushort cipherKey)
        {
            var frontKey = cipherKey & 0xFF00;
            if (frontKey == 0x0000)
            {
                return _00ciphers[cipherKey & 0x00FF];
            }
            if (frontKey == 0xC000)
            {
                return _C0ciphers[cipherKey & 0x00FF];
            }
            return null;
        }
    }
}
