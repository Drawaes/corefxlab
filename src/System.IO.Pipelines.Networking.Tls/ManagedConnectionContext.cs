using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed;
using System.IO.Pipelines.Networking.Tls.Managed.BulkCiphers;
using System.IO.Pipelines.Networking.Tls.Managed.Handshake;
using System.IO.Pipelines.Networking.Tls.Managed.Hash;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls
{
    public class ManagedConnectionContext : ISecureContext
    {
        private const int RandomLength = 32;
        private ManagedSecurityContext _context;
        private readonly bool _isServer;
        private ApplicationLayerProtocolIds _negotiatedProtocol;
        
        private bool _readyToSend;
        private bool _clientDataEncrypted;
        private bool _serverDataEncrypted;
        private byte[] _seedBuffer = new byte[s_masterSecretLabel.Length + RandomLength * 2];
        private ulong _clientSequenceNumber = 0;
        private ulong _serverSequenceNumber = 0;
        private CipherSuite _cipherSuite;
        private HashInstance _handshakeHash;
        private byte[] _clientNounce;
        private byte[] _serverNounce;
        private BulkCipherKey _clientKey;
        private BulkCipherKey _serverKey;
        private byte[] _masterSecret;
        private static readonly TlsRecordWriter<HandshakeMessageWriter<HandshakeServerHelloWriter>> _handshakeServerHelloWriter = new TlsRecordWriter<HandshakeMessageWriter<HandshakeServerHelloWriter>>();
        private static readonly TlsRecordWriter<HandshakeMessageWriter<HandshakeServerCertificateWriter>> _handshakeCertificateWriter = new TlsRecordWriter<HandshakeMessageWriter<HandshakeServerCertificateWriter>>();
        private static readonly TlsRecordWriter<HandshakeMessageWriter<HandshakeServerHelloDone>> _handshakeServerDoneWriter = new TlsRecordWriter<HandshakeMessageWriter<HandshakeServerHelloDone>>();
        private static readonly TlsRecordWriter<ChangeCipherSpec> _changeCipherSpecWriter = new TlsRecordWriter<ChangeCipherSpec>();
        private static readonly TlsRecordWriter<HandshakeMessageWriter<HandshakeServerFinishedWriter>> _handshakeFinishedWriter = new TlsRecordWriter<HandshakeMessageWriter<HandshakeServerFinishedWriter>>();
        private static readonly byte[] s_masterSecretLabel = Encoding.ASCII.GetBytes("master secret");
        private static readonly byte[] s_keyexpansionLabel = Encoding.ASCII.GetBytes("key expansion");
        private static readonly byte[] s_clientfinishedLabel = Encoding.ASCII.GetBytes("client finished");
        private static readonly byte[] s_serverfinishedLabel = Encoding.ASCII.GetBytes("server finished");
        private byte[] _serverVerifyData;


        private static readonly Task _cachedTask = Task.FromResult(0);

        public ManagedConnectionContext(ManagedSecurityContext context)
        {
            _context = context;
            Buffer.BlockCopy(s_masterSecretLabel,0,_seedBuffer,0,s_masterSecretLabel.Length);
        }

        public int HeaderSize { get; set; }
        public bool IsServer => _context.IsServer;
        public ApplicationLayerProtocolIds NegotiatedProtocol => _negotiatedProtocol;
        public bool ReadyToSend => _readyToSend;
        public CipherList Ciphers => _context.Ciphers;
        public int TrailerSize { get; set; }
        public CipherSuite CipherSuite => _cipherSuite;
        public ManagedSecurityContext SecurityContext => _context;
        public HashInstance HandshakeHash => _handshakeHash;
        public byte[] SeedBuffer => _seedBuffer;
        public byte[] ServerVerifyData => _serverVerifyData;
        public bool ServerDataEncrypted => _serverDataEncrypted;
        public BulkCipherKey ServerKey => _serverKey;

        public Task DecryptAsync(ReadableBuffer encryptedData, IPipelineWriter decryptedPipeline)
        {
            throw new NotImplementedException();
        }

        internal byte[] GetServerNounce(ulong serverSequenceNumber)
        {
            var s = new Span<byte>(_serverNounce,4);
            s.Write64BitNumber(serverSequenceNumber);
            return _serverNounce;
        }

        internal void SetMasterSecret(byte[] masterSecret)
        {
            _masterSecret = masterSecret;
        }

        internal ulong GetServerSequenceNumber()
        {
            ulong current = _serverSequenceNumber;
            _serverSequenceNumber ++;
            return current;
        }

        public Task EncryptAsync(ReadableBuffer unencryptedData, IPipelineWriter encryptedPipeline)
        {
            throw new NotImplementedException();
        }

        public Task ProcessContextMessageAsync(IPipelineWriter writer)
        {
            throw new NotImplementedException();
        }

        public void SetClientKeyAndNounce(BulkCipherKey key, byte[] nounce)
        {
            _clientNounce = new byte[12];
            Buffer.BlockCopy(nounce,0,_clientNounce,0,nounce.Length);
            _clientKey = key;
        }
        public void SetServerKeyAndNounce(BulkCipherKey key, byte[] nounce)
        {
            _serverNounce = new byte[12];
            Buffer.BlockCopy(nounce, 0, _serverNounce, 0, nounce.Length);
            _serverKey = key;
        }

        public void SetClientRandom(ReadableBuffer buffer)
        {
            var span = new Span<byte>(_seedBuffer, s_masterSecretLabel.Length);
            buffer.CopyTo(span);
        }

        public void SetServerRandom(Memory<byte> memory)
        {
            var span = new Span<byte>(_seedBuffer,s_masterSecretLabel.Length + RandomLength);
            memory.CopyTo(span);
        }

        public void SetSeedKeyExpansion()
        {
            Buffer.BlockCopy(s_keyexpansionLabel, 0, _seedBuffer,0,s_keyexpansionLabel.Length);
            var tmp = _seedBuffer.ToArray();
            Buffer.BlockCopy(tmp,s_keyexpansionLabel.Length,_seedBuffer,s_keyexpansionLabel.Length + RandomLength,RandomLength);
            Buffer.BlockCopy(tmp,s_keyexpansionLabel.Length + RandomLength, _seedBuffer, s_keyexpansionLabel.Length, RandomLength);
        }
        
        public void SetCipherSuite(CipherSuite info)
        {
            _handshakeHash = info.Hash.GetLongRunningHash();
            _cipherSuite = info;
        }

        public Task ProcessContextMessageAsync(ReadableBuffer readBuffer, IPipelineWriter writer)
        {
            var frameType = (TlsFrameType)readBuffer.ReadBigEndian<byte>();
            readBuffer = readBuffer.Slice(1);
            var versionMajor = readBuffer.ReadBigEndian<byte>();
            readBuffer = readBuffer.Slice(1);
            var versionMinor = readBuffer.ReadBigEndian<byte>();
            readBuffer = readBuffer.Slice(1);
            var size = readBuffer.ReadBigEndian<ushort>();
            readBuffer = readBuffer.Slice(2);

            if(frameType == TlsFrameType.ChangeCipherSpec)
            {
                _clientDataEncrypted = true;
                return _cachedTask;
            }
            if(_clientDataEncrypted)
            {
                //_handshakeHash.HashData(readBuffer.Slice(8));

                byte[] additionalData = new byte[13];
                var addSpan = new Span<byte>(additionalData);
                addSpan.Write64BitNumber(_clientSequenceNumber);
                _clientSequenceNumber ++;
                addSpan = addSpan.Slice(8);
                addSpan.Write(frameType);
                addSpan = addSpan.Slice(1);
                addSpan.Write(versionMajor);
                addSpan = addSpan.Slice(1);
                addSpan.Write(versionMinor);
                addSpan = addSpan.Slice(1);
                addSpan.Write16BitNumber((ushort)(size - 8 - 16));

                var s = new Span<byte>(_clientNounce,4);
                
                readBuffer.Slice(0,8).CopyTo(s);
                readBuffer = readBuffer.Slice(8);
                var addLength = 16;
                var encrypted = readBuffer.Slice(0,addLength).ToArray();
                readBuffer = readBuffer.Slice(addLength);
                var tag = readBuffer.ToArray();
                
                var decData = _clientKey.Decrypt(_clientNounce, encrypted,tag, additionalData);
                _handshakeHash.HashData(decData);
                //_handshakeHash.HashData(tag);
                var hashResult = _handshakeHash.Finish();
                var verifyData = new byte[12];
                //ClientKeyExchange.P_hash(_cipherSuite.Hmac,verifyData,_masterSecret, Enumerable.Concat(s_clientfinishedLabel,hashResult).ToArray());
                //PRF(master_secret, finished_label, Hash(handshake_messages))
                //[0..verify_data_length - 1];
                _readyToSend = true;
                var writeBuffer = writer.Alloc();
                _changeCipherSpecWriter.WriteMessage(ref writeBuffer, this);
                writeBuffer.Commit();
                _serverDataEncrypted = true;
                ClientKeyExchange.P_hash(_cipherSuite.Hmac, verifyData, _masterSecret, Enumerable.Concat(s_serverfinishedLabel, hashResult).ToArray());
                _serverVerifyData = verifyData;
                writeBuffer = writer.Alloc();
                _handshakeFinishedWriter.WriteMessage(ref writeBuffer,this);
                System.IO.File.WriteAllText("C:\\Code\\KeyLog\\ServerFinished.txt", BitConverter.ToString(writeBuffer.AsReadableBuffer().ToArray()));
                return writeBuffer.FlushAsync();

            }
            var messageType = (HandshakeMessageType)readBuffer.ReadBigEndian<byte>();
            
            switch (messageType)
            {
                case HandshakeMessageType.ClientHello:
                    ClientHello.ProcessClientHello(readBuffer, this);
                    var writeBuffer = writer.Alloc();
                    _handshakeServerHelloWriter.WriteMessage(ref writeBuffer, this);
                    writeBuffer.Commit();
                    writeBuffer = writer.Alloc();
                    _handshakeCertificateWriter.WriteMessage(ref writeBuffer, this);
                    writeBuffer.Commit();
                    writeBuffer = writer.Alloc();
                    _handshakeServerDoneWriter.WriteMessage(ref writeBuffer, this);
                    return writeBuffer.FlushAsync();
                case HandshakeMessageType.ClientKeyExchange:
                    ClientKeyExchange.ProcessClientKeyExchange(readBuffer, this);
                    return _cachedTask;
            //    default:
            //        throw new NotImplementedException();
            }
            throw new NotImplementedException();
        }

        public void Dispose()
        {
            _handshakeHash.Dispose();
        }
    }
}
