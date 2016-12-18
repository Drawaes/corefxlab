using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.BulkCipher;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.KeyExchange;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal
{
    internal class CipherSuite
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

            var keyExchangeAndBulk = remainingString.Split(new string[] { "_WITH_" }, StringSplitOptions.None);

            _keyProvider = keyFactory.GetKeyExchange(keyExchangeAndBulk[0]);

            //Get the hash and bulk
            var hash = keyExchangeAndBulk[1].Substring(keyExchangeAndBulk[1].LastIndexOf('_') + 1);
            var bulk = keyExchangeAndBulk[1].Substring(0, keyExchangeAndBulk[1].Length - hash.Length - 1);

            if (bulk.StartsWith("3"))
            {
                bulk = "Triple" + bulk.Substring(1);
            }
            var bulkCipher = (BulkCipherType)Enum.Parse(typeof(BulkCipherType), bulk, true);
            _bulkCipher = cipherFactory.GetCipher(bulkCipher);

            _hash = hmacFactory.GetHashProvider(hash);
            _hmac = hmacFactory.GetHmacProvider(hash);
        }

        public string CipherString => _cipherString;
        public ushort CipherId => _cipherId;
        public IKeyExchangeProvider KeyExchange => _keyProvider;
        public HashProvider Hmac => _hmac;
        public HashProvider Hash => _hash;
        public BulkCipherProvider BulkCipher => _bulkCipher;
        public int KeyMaterialRequired => 2 * (_bulkCipher.KeySizeInBytes + (_bulkCipher.RequiresHmac ? _hmac.HashLength : 0) + _bulkCipher.NounceSaltLength);

        public override string ToString()
        {
            return _cipherString;
        }

        public bool IsValid()
        {
            if (_bulkCipher == null || _hmac == null || _hash == null || _keyProvider == null)
            {
                return false;
            }
            return true;
        }

        internal unsafe void ProcessKeyMaterial(ConnectionState state, byte[] keyMaterial)
        {
            fixed (byte* keyPtr = keyMaterial)
            {
                byte[] clientHmac = null;
                byte[] serverHmac = null;
                var currentPtr = keyPtr;
                if (BulkCipher.RequiresHmac)
                {
                    clientHmac = (new Span<byte>(currentPtr, Hmac.HashLength)).ToArray();
                    currentPtr += Hmac.HashLength;
                    serverHmac = (new Span<byte>(currentPtr, Hmac.HashLength)).ToArray();
                    currentPtr += Hmac.HashLength;
                }

                var clientKey = BulkCipher.GetCipherKey(currentPtr, BulkCipher.KeySizeInBytes);
                clientKey.HmacKey = clientHmac;
                currentPtr = keyPtr + BulkCipher.KeySizeInBytes;
                var serverKey = BulkCipher.GetCipherKey(currentPtr, BulkCipher.KeySizeInBytes);
                serverKey.HmacKey = serverHmac;
                currentPtr = currentPtr + BulkCipher.KeySizeInBytes;

                
                if (BulkCipher.NounceSaltLength > 0)
                {
                    clientKey.SetNouce(new Span<byte>(currentPtr, BulkCipher.NounceSaltLength));
                    currentPtr = currentPtr + BulkCipher.NounceSaltLength;
                    serverKey.SetNouce(new Span<byte>(currentPtr, BulkCipher.NounceSaltLength));
                }

                state.ClientKey = clientKey;
                state.ServerKey = serverKey;
            }
        }
    }
}
