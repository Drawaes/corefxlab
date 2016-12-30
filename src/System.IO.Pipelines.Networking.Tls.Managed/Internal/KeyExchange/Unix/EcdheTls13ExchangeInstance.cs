using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Unix;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Unix;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.KeyExchange.Unix
{
    internal class EcdheTls13ExchangeInstance : ITls13KeyExchangeInstance
    {
        private int _nid;
        private EcdhExchangeProvider _provider;
        private NamedGroup _group;
        private IntPtr _eKey;
        private int _eKeySize;
        private byte[] _handshakeSecret;
        private bool _hasClientKey;

        public EcdheTls13ExchangeInstance(int nid, EcdhExchangeProvider provider, NamedGroup group)
        {
            _group = group;
            _nid = nid;
            _provider = provider;
        }

        public bool HasClientKey => _hasClientKey;
        public NamedGroup Group => _group;
        public int KeySize => _eKeySize;

        public unsafe void SetClientKey(ReadableBuffer readableBuffer)
        {
            GenerateEphemeralKey();
            IntPtr clientsPubKey = InteropEcdh.ImportPublicKey(_eKey, readableBuffer.ToArray(), _nid);
            IntPtr ctx = InteropEcdh.EVP_PKEY_CTX_new(_eKey, IntPtr.Zero);
            OpenSslPal.CheckOpenSslError(InteropEcdh.EVP_PKEY_derive_init(ctx));
            OpenSslPal.CheckOpenSslError(InteropEcdh.EVP_PKEY_derive_set_peer(ctx, clientsPubKey));
            IntPtr size = IntPtr.Zero;
            OpenSslPal.CheckOpenSslError(InteropEcdh.EVP_PKEY_derive(ctx, null, ref size));
            var tmpBuffer = new byte[size.ToInt32()];
            fixed (void* tPtr = tmpBuffer)
            {
                OpenSslPal.CheckOpenSslError(InteropEcdh.EVP_PKEY_derive(ctx, tPtr, ref size));
            }
            _handshakeSecret = tmpBuffer;
            _hasClientKey = true;

        }

        private void GenerateEphemeralKey()
        {
            _eKey = InteropEcdh.NewEcdhePKey(_nid);
            _eKeySize = ((InteropEcdh.EVP_PKEY_bits(_eKey) + 7) / 8) * 2;
        }

        public void GetPublicKey(ref WritableBuffer outBuffer)
        {
            InteropEcdh.GetPublicKey(_eKey, outBuffer.Memory.Slice(0, _eKeySize + 1));
            outBuffer.Advance(_eKeySize + 1);
        }

        public unsafe void GenerateTrafficKeys(IConnectionState state)
        {
            var hash = new byte[state.HandshakeHash.HashLength];
            fixed (byte* h = hash)
            {
                state.HandshakeHash.Finish(h, hash.Length, false);

                var serverHandshakeTrafficSecret = TlsSpec.Tls13Utils.DerviceSecret(state.CipherSuite.Hash, _handshakeSecret, "server handshake traffic secret", hash);
                var clientHandshakeTrafficSecret = TlsSpec.Tls13Utils.DerviceSecret(state.CipherSuite.Hash, _handshakeSecret, "client handshake traffic secret", hash);

                var serverKey = TlsSpec.Tls13Utils.HKDFExpandLabel(state.CipherSuite.Hash, serverHandshakeTrafficSecret, "key", new byte[0],state.CipherSuite.BulkCipher.KeySizeInBytes);
                var serverNounce = TlsSpec.Tls13Utils.HKDFExpandLabel(state.CipherSuite.Hash, serverHandshakeTrafficSecret, "iv", new byte[0], 12);


            }
        }
    }
}
