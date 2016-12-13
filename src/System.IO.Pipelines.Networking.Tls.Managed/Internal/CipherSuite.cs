using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.BulkCipher;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.KeyExchange;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal
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
            //Remove TLS_ from the front of the string
            var remainingString = cipherString.Substring(4);

            var keyExchangeAndBulk = remainingString.Split(new string[] { "_WITH_" },StringSplitOptions.None);
            
            //Get the hash and bulk
            var hash = keyExchangeAndBulk[1].Substring(keyExchangeAndBulk[1].LastIndexOf('_') + 1);
            var bulk = keyExchangeAndBulk[1].Substring(0, hash.Length);

            
        }
    }
}
