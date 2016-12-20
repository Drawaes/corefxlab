using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.BulkCiphers;
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
        private readonly IHashProvider _hashProvider;
        private readonly IBulkCipherProvider _bulkCipherProvider;
        private readonly IKeyExchangeProvider _keyProvider;

        public CipherSuite(ushort cipherId, string cipherString, IBulkCipherPal bulkFactory, IHashPal hashFactory, IKeyExchangePal keyFactory)
        {
            _cipherId = cipherId;
            _cipherString = cipherString;
            //Remove TLS_ from the front of the string
            var remainingString = cipherString.Substring(4);
            var keyExchangeAndBulk = remainingString.Split(new string[] { "_WITH_" }, StringSplitOptions.None);
            var hash = keyExchangeAndBulk[1].Substring(keyExchangeAndBulk[1].LastIndexOf('_') + 1);
            var bulk = keyExchangeAndBulk[1].Substring(0, keyExchangeAndBulk[1].Length - hash.Length - 1);
            if (bulk.StartsWith("3"))
            {
                bulk = "Triple" + bulk.Substring(1);
            }
            _hashProvider = hashFactory.GetHashProvider(hash);
            _bulkCipherProvider = bulkFactory.GetCipher(bulk);
            _keyProvider = keyFactory.GetKeyExchange(keyExchangeAndBulk[0]);
        }

        public string CipherString => _cipherString;
        public ushort CipherId => _cipherId;
        public IKeyExchangeProvider KeyExchange => _keyProvider;
        public IBulkCipherProvider BulkCipher => _bulkCipherProvider;
        public IHashProvider Hash => _hashProvider;
        public int KeyMaterialRequired => 2 * (_bulkCipherProvider.KeySizeInBytes + (_bulkCipherProvider.RequiresHmac ? _hashProvider.HashLength : 0) + _bulkCipherProvider.NonceSaltLength);

        internal unsafe void ProcessKeyMaterial(ConnectionState state, byte[] keyMaterial)
        {
            fixed (byte* keyPtr = keyMaterial)
            {
                byte[] clientHmac = null;
                byte[] serverHmac = null;
                var currentPtr = keyPtr;
                if (BulkCipher.RequiresHmac)
                {
                    clientHmac = (new Span<byte>(currentPtr, Hash.HashLength)).ToArray();
                    currentPtr += Hash.HashLength;
                    serverHmac = (new Span<byte>(currentPtr, Hash.HashLength)).ToArray();
                    currentPtr += Hash.HashLength;
                }

                var clientKey = BulkCipher.GetCipherKey(currentPtr, BulkCipher.KeySizeInBytes);
                clientKey.HmacKey = clientHmac;
                currentPtr = keyPtr + BulkCipher.KeySizeInBytes;
                var serverKey = BulkCipher.GetCipherKey(currentPtr, BulkCipher.KeySizeInBytes);
                serverKey.HmacKey = serverHmac;
                currentPtr = currentPtr + BulkCipher.KeySizeInBytes;


                if (BulkCipher.NonceSaltLength > 0)
                {
                    clientKey.SetNonce(new Span<byte>(currentPtr, BulkCipher.NonceSaltLength));
                    currentPtr = currentPtr + BulkCipher.NonceSaltLength;
                    serverKey.SetNonce(new Span<byte>(currentPtr, BulkCipher.NonceSaltLength));
                }

                state.ClientKey = clientKey;
                state.ServerKey = serverKey;
            }
        }

        public bool IsValid()
        {
            if (_bulkCipherProvider == null || _hashProvider == null || _keyProvider == null)
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
