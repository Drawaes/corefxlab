using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Handshake;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Unix;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.TlsSpec;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.KeyExchange.Unix
{
    internal class EcdheExchangeInstance : IKeyExchangeInstance
    {
        private readonly ICertificate _certificate;
        private readonly ConnectionState _state;
        private readonly EcdhExchangeProvider _exchangeProvider;
        private EllipticCurves _curveType;
        private int _nid;
        private IntPtr _eKey;
        private int _eKeySize;

        public EcdheExchangeInstance(ICertificate certificate, ConnectionState state, EcdhExchangeProvider provider)
        {
            _certificate = certificate;
            _state = state;
            _exchangeProvider = provider;
        }

        public void ProcessSupportedGroupsExtension(ReadableBuffer buffer)
        {
            var bufferTemp = buffer;
            buffer = buffer.Slice(2);
            while (buffer.Length > 0)
            {
                var value = buffer.ReadBigEndian<ushort>();
                int nid = _exchangeProvider.GetNid(value);
                if (nid != 0)
                {
                    _nid = nid;
                    _curveType = (EllipticCurves) value;
                    return;
                }
                buffer = buffer.Slice(2);
            }
            Alerts.AlertException.ThrowAlertException(Alerts.AlertType.Handshake_Failure);
        }

        public void ProcessEcPointFormats(ReadableBuffer buffer)
        {
        }

        public unsafe void WriteServerKeyExchange(ref WritableBuffer buffer)
        {
            var frame = new FrameWriter(ref buffer, TlsFrameType.Handshake, _state);
            var hw = new HandshakeWriter(ref buffer, _state, HandshakeMessageType.ServerKeyExchange);

            GenerateEphemeralKey();

            //5 for the header
            var messageSize = 5 + _eKeySize;
            buffer.Ensure(messageSize);
            var bookMark = buffer.Memory;

            WriteServerECDHParams(ref buffer);

            var hash = _state.CipherSuite.Hash.GetLongRunningHash(null);
            hash.HashData(_state.ClientRandom);
            hash.HashData(_state.ServerRandom);
            hash.HashData(bookMark.Slice(0, messageSize));

            buffer.Ensure(2);
            buffer.WriteBigEndian((byte)_state.CipherSuite.Hash.HashType);
            buffer.WriteBigEndian((byte)_certificate.CertificateType);

            var hashResult = stackalloc byte[hash.HashLength];
            hash.Finish(hashResult, hash.HashLength, true);

            buffer.Ensure(_certificate.SignatureSize + 2);
            buffer.WriteBigEndian((ushort)_certificate.SignatureSize);

            _certificate.SignHash(_state.CipherSuite.Hash, buffer.Memory.Slice(0, _certificate.SignatureSize), hashResult, hash.HashLength);
            buffer.Advance(_certificate.SignatureSize);

            hw.Finish(ref buffer);
            frame.Finish(ref buffer);
        }

        private unsafe void WriteServerECDHParams(ref WritableBuffer buffer)
        {
            //Named curve
            buffer.WriteLittleEndian((byte)3);
            //Curve type
            buffer.WriteBigEndian((ushort)_curveType);
            //-------------------EC PARAMS WRITTEN

            buffer.WriteBigEndian((byte)(_eKeySize + 1));
            
            InteropEcdh.GetPublicKey(_eKey,buffer.Memory.Slice(0, _eKeySize + 1));
            buffer.Advance(_eKeySize+1);
            //-------------------Written Server ECHDE PARAMS
        }

        private void GenerateEphemeralKey()
        {
            _eKey = InteropEcdh.NewEcdhePKey(_nid);
            _eKeySize =( (InteropEcdh.EVP_PKEY_bits(_eKey) + 7)/8) *2;
        }

        public byte[] ProcessClientKeyExchange(ReadableBuffer buffer)
        {
            _state.HandshakeHash.HashData(buffer);
            buffer = buffer.Slice(1); // Slice off type
            uint contentSize = buffer.ReadBigEndian<ushort>();
            buffer = buffer.Slice(2);
            contentSize = (contentSize << 8) + buffer.ReadBigEndian<byte>();
            buffer = buffer.Slice(1);
            if (buffer.Length != contentSize)
            {
                throw new IndexOutOfRangeException($"The message buffer contains the wrong amount of data for our operation");
            }

            var keyLength = buffer.ReadBigEndian<byte>();
            keyLength--;
            buffer = buffer.Slice(1);
            if(buffer.Length -1 != keyLength )
            {
                throw new IndexOutOfRangeException("Bad length or compression type");
            }

            /*To deserialize the public key:

Pass the octets to EC_POINT_oct2point() to get an EC_POINT.
Pass the EC_POINT to EC_KEY_set_public_key() to get an EC_KEY.
Pass the EC_KEY to EVP_PKEY_set1_EC_KEY to get an EVP_KEY.*/

            //Need to make a poiint object first?

            //int EC_POINT_oct2point(const EC_GROUP *group, EC_POINT *p,
            //const unsigned char* buf, size_t len, BN_CTX* ctx);

            //Need to create a key object first?

            //int EC_KEY_set_public_key(EC_KEY *key, const EC_POINT *pub);

            //need to create a EVP_KEY first?

            //int EVP_PKEY_set1_EC_KEY(EVP_PKEY *pkey, struct ec_key_st *key);





        }
    }
}
