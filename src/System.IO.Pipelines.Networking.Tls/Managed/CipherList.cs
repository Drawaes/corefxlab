﻿using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Hash;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed
{
    public class CipherList
    {
        private readonly CipherInfo[] _00ciphers = new CipherInfo[255];
        private readonly CipherInfo[] _0Cciphers = new CipherInfo[255];
        private readonly BulkCiphers.BulkCipherFactory _bulkCipherFactory = new BulkCiphers.BulkCipherFactory();
        private readonly HashFactory _hmacFactory = new HashFactory();

        public CipherList()
        {
            _00ciphers[0x0A] = new CipherInfo(0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", _bulkCipherFactory, _hmacFactory);
            _00ciphers[0x0D] = new CipherInfo(0x000D, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA" ,_bulkCipherFactory, _hmacFactory);
            _00ciphers[0x10] = new CipherInfo(0x0010, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA" ,_bulkCipherFactory, _hmacFactory);
            _00ciphers[0x13] = new CipherInfo(0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA" ,_bulkCipherFactory, _hmacFactory);
            _00ciphers[0x16] = new CipherInfo(0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA" ,_bulkCipherFactory, _hmacFactory);
            _00ciphers[0x2F] = new CipherInfo(0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA", _bulkCipherFactory, _hmacFactory);
            _00ciphers[0x30] = new CipherInfo(0x0030, "TLS_DH_DSS_WITH_AES_128_CBC_SHA", _bulkCipherFactory, _hmacFactory);
            _00ciphers[0x31] = new CipherInfo(0x0031, "TLS_DH_RSA_WITH_AES_128_CBC_SHA", _bulkCipherFactory, _hmacFactory);
            _00ciphers[0x32] = new CipherInfo(0x0032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", _bulkCipherFactory, _hmacFactory);
            _00ciphers[0x33] = new CipherInfo(0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", _bulkCipherFactory, _hmacFactory);
            _00ciphers[0x35] = new CipherInfo(0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA", _bulkCipherFactory, _hmacFactory);
            _00ciphers[0x36] = new CipherInfo(0x0036, "TLS_DH_DSS_WITH_AES_256_CBC_SHA", _bulkCipherFactory, _hmacFactory);
            _00ciphers[0x37] = new CipherInfo(0x0037, "TLS_DH_RSA_WITH_AES_256_CBC_SHA", _bulkCipherFactory, _hmacFactory);
            _00ciphers[0x38] = new CipherInfo(0x0038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0x39] = new CipherInfo(0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", _bulkCipherFactory, _hmacFactory);
            _00ciphers[0x3C] = new CipherInfo(0x003C, "TLS_RSA_WITH_AES_128_CBC_SHA256",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0x3D] = new CipherInfo(0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0x3E] = new CipherInfo(0x003E, "TLS_DH_DSS_WITH_AES_128_CBC_SHA256", _bulkCipherFactory, _hmacFactory);
            _00ciphers[0x3F] = new CipherInfo(0x003F, "TLS_DH_RSA_WITH_AES_128_CBC_SHA256", _bulkCipherFactory, _hmacFactory);
            _00ciphers[0x40] = new CipherInfo(0x0040, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0x4A] = new CipherInfo(0x004A, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0x4B] = new CipherInfo(0x004B, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0x4C] = new CipherInfo(0x004C, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0x67] = new CipherInfo(0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0x68] = new CipherInfo(0x0068, "TLS_DH_DSS_WITH_AES_256_CBC_SHA256",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0x69] = new CipherInfo(0x0069, "TLS_DH_RSA_WITH_AES_256_CBC_SHA256",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0x6A] = new CipherInfo(0x006A, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0x6B] = new CipherInfo(0x006B, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0x8B] = new CipherInfo(0x008B, "TLS_PSK_WITH_3DES_EDE_CBC_SHA",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0x8C] = new CipherInfo(0x008C, "TLS_PSK_WITH_AES_128_CBC_SHA",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0x8D] = new CipherInfo(0x008D, "TLS_PSK_WITH_AES_256_CBC_SHA",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0x8F] = new CipherInfo(0x008F, "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0x90] = new CipherInfo(0x0090, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0x91] = new CipherInfo(0x0091, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0x93] = new CipherInfo(0x0093, "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0x94] = new CipherInfo(0x0094, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0x95] = new CipherInfo(0x0095, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0x9C] = new CipherInfo(0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0x9D] = new CipherInfo(0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0x9E] = new CipherInfo(0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0x9F] = new CipherInfo(0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0xA0] = new CipherInfo(0x00A0, "TLS_DH_RSA_WITH_AES_128_GCM_SHA256",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0xA1] = new CipherInfo(0x00A1, "TLS_DH_RSA_WITH_AES_256_GCM_SHA384",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0xA2] = new CipherInfo(0x00A2, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0xA3] = new CipherInfo(0x00A3, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0xA4] = new CipherInfo(0x00A4, "TLS_DH_DSS_WITH_AES_128_GCM_SHA256",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0xA5] = new CipherInfo(0x00A5, "TLS_DH_DSS_WITH_AES_256_GCM_SHA384",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0xA8] = new CipherInfo(0x00A8, "TLS_PSK_WITH_AES_128_GCM_SHA256",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0xA9] = new CipherInfo(0x00A9, "TLS_PSK_WITH_AES_256_GCM_SHA384",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0xAA] = new CipherInfo(0x00AA, "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0xAB] = new CipherInfo(0x00AB, "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0xAC] = new CipherInfo(0x00AC, "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0xAD] = new CipherInfo(0x00AD, "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0xAE] = new CipherInfo(0x00AE, "TLS_PSK_WITH_AES_128_CBC_SHA256",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0xAF] = new CipherInfo(0x00AF, "TLS_PSK_WITH_AES_256_CBC_SHA384",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0xB2] = new CipherInfo(0x00B2, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0xB3] = new CipherInfo(0x00B3, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0xB6] = new CipherInfo(0x00B6, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256",_bulkCipherFactory, _hmacFactory);
            _00ciphers[0xB7] = new CipherInfo(0x00B7, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384",_bulkCipherFactory, _hmacFactory);
            _0Cciphers[0x03] = new CipherInfo(0x0C03, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",_bulkCipherFactory, _hmacFactory);
            _0Cciphers[0x04] = new CipherInfo(0x0C04, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",_bulkCipherFactory, _hmacFactory);
            _0Cciphers[0x05] = new CipherInfo(0x0C05, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",_bulkCipherFactory, _hmacFactory);
            _0Cciphers[0x08] = new CipherInfo(0x0C08, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",_bulkCipherFactory, _hmacFactory);
            _0Cciphers[0x09] = new CipherInfo(0x0C09, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",_bulkCipherFactory, _hmacFactory);
            _0Cciphers[0x0A] = new CipherInfo(0x0C0A, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",_bulkCipherFactory, _hmacFactory);
            _0Cciphers[0x0D] = new CipherInfo(0x0C0D, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",_bulkCipherFactory, _hmacFactory);
            _0Cciphers[0x0E] = new CipherInfo(0x0C0E, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",_bulkCipherFactory, _hmacFactory);
            _0Cciphers[0x0F] = new CipherInfo(0x0C0F, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",_bulkCipherFactory, _hmacFactory);
            _0Cciphers[0x12] = new CipherInfo(0x0C12, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",_bulkCipherFactory, _hmacFactory);
            _0Cciphers[0x13] = new CipherInfo(0x0C13, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",_bulkCipherFactory, _hmacFactory);
            _0Cciphers[0x14] = new CipherInfo(0x0C14, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",_bulkCipherFactory, _hmacFactory);
            _0Cciphers[0x23] = new CipherInfo(0x0C23, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",_bulkCipherFactory, _hmacFactory);
            _0Cciphers[0x24] = new CipherInfo(0x0C24, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",_bulkCipherFactory, _hmacFactory);
            _0Cciphers[0x25] = new CipherInfo(0x0C25, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",_bulkCipherFactory, _hmacFactory);
            _0Cciphers[0x26] = new CipherInfo(0x0C26, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",_bulkCipherFactory, _hmacFactory);
            _0Cciphers[0x27] = new CipherInfo(0x0C27, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",_bulkCipherFactory, _hmacFactory);
            _0Cciphers[0x28] = new CipherInfo(0x0C28, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",_bulkCipherFactory, _hmacFactory);
            _0Cciphers[0x29] = new CipherInfo(0x0C29, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",_bulkCipherFactory, _hmacFactory);
            _0Cciphers[0x2A] = new CipherInfo(0x0C2A, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",_bulkCipherFactory, _hmacFactory);
            _0Cciphers[0x2B] = new CipherInfo(0x0C2B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",_bulkCipherFactory, _hmacFactory);
            _0Cciphers[0x2C] = new CipherInfo(0x0C2C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",_bulkCipherFactory, _hmacFactory);
            _0Cciphers[0x2D] = new CipherInfo(0x0C2D, "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",_bulkCipherFactory, _hmacFactory);
            _0Cciphers[0x2E] = new CipherInfo(0x0C2E, "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",_bulkCipherFactory, _hmacFactory);
            _0Cciphers[0x2F] = new CipherInfo(0x0C2F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",_bulkCipherFactory, _hmacFactory);
            _0Cciphers[0x30] = new CipherInfo(0x0C30, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",_bulkCipherFactory, _hmacFactory);
            _0Cciphers[0x31] = new CipherInfo(0x0C31, "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",_bulkCipherFactory, _hmacFactory);
            _0Cciphers[0x32] = new CipherInfo(0x0C32, "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",_bulkCipherFactory, _hmacFactory);
            _0Cciphers[0x34] = new CipherInfo(0x0C34, "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA",_bulkCipherFactory, _hmacFactory);
            _0Cciphers[0x35] = new CipherInfo(0x0C35, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",_bulkCipherFactory, _hmacFactory);
            _0Cciphers[0x36] = new CipherInfo(0x0C36, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",_bulkCipherFactory, _hmacFactory);
            _0Cciphers[0x37] = new CipherInfo(0x0C37, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",_bulkCipherFactory, _hmacFactory);
            _0Cciphers[0x38] = new CipherInfo(0x0C38, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",_bulkCipherFactory, _hmacFactory);

            for (int i = 0; i < _0Cciphers.Length; i++)
            {
                if (_0Cciphers[i]?.IsValid() != true)
                {
                    _0Cciphers[i] = null;
                }
                if (_00ciphers[i]?.IsValid() != true)
                {
                    _00ciphers[i] = null;
                }
            }
            _hmacFactory.Init();
        }

        public void SetSupported(KeyExchangeCipher keyExchangeAlgo)
        {
            for (int i = 0; i < _0Cciphers.Length; i++)
            {
                if (_0Cciphers[i] != null && _0Cciphers[i].ExchangeCipher != keyExchangeAlgo)
                {
                    _0Cciphers[i] = null;
                }
                if (_00ciphers[i] != null && _00ciphers[i].ExchangeCipher != keyExchangeAlgo)
                {
                    _00ciphers[i] = null;
                }
            }
        }

        public CipherInfo GetCipherInfo(ushort cipherKey)
        {
            var frontKey = cipherKey & 0xFF00;
            if (frontKey == 0x0000)
            {
                return _00ciphers[cipherKey & 0x00FF];
            }
            if (frontKey == 0xC000)
            {
                return _0Cciphers[cipherKey & 0x00FF];
            }
            return null;
        }
    }
}
