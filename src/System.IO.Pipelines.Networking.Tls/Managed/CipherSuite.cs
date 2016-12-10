using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.BulkCiphers;
using System.IO.Pipelines.Networking.Tls.Managed.Hash;
using System.IO.Pipelines.Networking.Tls.Managed.KeyExchange;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed
{
    public class CipherSuite
    {
        private readonly string _cipherString;
        private readonly ushort _cipherId;
        private readonly HashProvider _hmac;
        private readonly HashProvider _hash;
        private readonly BulkCipherProvider _bulkCipher;
        private readonly IKeyExchangeProvider _keyProvider;

        public CipherSuite(ushort cipherId, string cipherString, BulkCipherFactory cipherFactory, HashFactory hmacFactory, KeyExchangeFactory keyFactory)
        {
            _cipherString = cipherString;
            _cipherId = cipherId;

            var remainingString = cipherString.Substring(4);
            var index = remainingString.IndexOf("WITH");
            var exchangeCipher = remainingString.Substring(0, index - 1);
            _keyProvider = keyFactory.GetKeyProvider((KeyExchangeType)Enum.Parse(typeof(KeyExchangeType), exchangeCipher, true));
            remainingString = remainingString.Substring(index + "WITH".Length + 1);
            var lastIndex = remainingString.LastIndexOf("_");
            var lastPart = remainingString.Substring(lastIndex + 1);
            var hashName = (HashType)Enum.Parse(typeof(HashType), lastPart, true);
            _hmac = hmacFactory.GetHmacProvider(hashName);
            _hash = hmacFactory.GetHashProvider(hashName);

            remainingString = remainingString.Substring(0, lastIndex);
            if (remainingString.StartsWith("3"))
            {
                remainingString = "Triple" + remainingString.Substring(1);
            }
            var bulkCipher = (BulkCipherType)Enum.Parse(typeof(BulkCipherType), remainingString, true);
            _bulkCipher = cipherFactory.GetCipher(bulkCipher);
        }

        public string CipherString => _cipherString;
        public ushort CipherId => _cipherId;
        public IKeyExchangeProvider KeyExchange => _keyProvider;
        public HashProvider Hmac => _hmac;
        public HashProvider Hash => _hash;
        public BulkCipherProvider BulkCipher => _bulkCipher;
        public int KeyMaterialRequired => 2 * (_bulkCipher.KeySizeInBytes + (_bulkCipher.RequiresHmac ? _hmac.BlockLength : 0) + _bulkCipher.NounceSaltLength);

        public bool IsValid()
        {
            if (_bulkCipher == null || _hmac == null || _hash == null || _keyProvider == null)
            {
                return false;
            }
            return true;
        }
                
        public override string ToString()
        {
            return _cipherString;
        }
    }
}
