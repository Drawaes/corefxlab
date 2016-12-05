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
        private byte[] _seedBuffer = new byte[s_masterSecretLabel.Length + RandomLength * 2];
        private CipherInfo _cipherSuite;
        private HashInstance _handshakeHash;
        private byte[] _clientNounce;
        private BulkCipherKey _clientKey;
        private static readonly TlsRecordWriter<HandshakeMessageWriter<HandshakeServerHelloWriter>> _handshakeServerHelloWriter = new TlsRecordWriter<HandshakeMessageWriter<HandshakeServerHelloWriter>>();
        private static readonly TlsRecordWriter<HandshakeMessageWriter<HandshakeServerCertificateWriter>> _handshakeCertificateWriter = new TlsRecordWriter<HandshakeMessageWriter<HandshakeServerCertificateWriter>>();
        private static readonly TlsRecordWriter<HandshakeMessageWriter<HandshakeServerHelloDone>> _handshakeServerDoneWriter = new TlsRecordWriter<HandshakeMessageWriter<HandshakeServerHelloDone>>();
        private static readonly byte[] s_masterSecretLabel = Encoding.ASCII.GetBytes("master secret");
        private static readonly byte[] s_keyexpansionLabel = Encoding.ASCII.GetBytes("key expansion");
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
        public CipherInfo CipherSuite => _cipherSuite;
        public ManagedSecurityContext SecurityContext => _context;
        public HashInstance HandshakeHash => _handshakeHash;
        public byte[] SeedBuffer => _seedBuffer;
        
        public Task DecryptAsync(ReadableBuffer encryptedData, IPipelineWriter decryptedPipeline)
        {
            throw new NotImplementedException();
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
        
        public void SetCipherSuite(CipherInfo info)
        {
            _handshakeHash = info.Hash.GetLongRunningHash();
            _cipherSuite = info;
        }

        public Task ProcessContextMessageAsync(ReadableBuffer readBuffer, IPipelineWriter writer)
        {
            byte[] additionalData = new byte[5 + 8];
            var addSpan = new Span<byte>(additionalData,8);
            readBuffer.Slice(0,5).CopyTo(addSpan);
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
                var s = new Span<byte>(_clientNounce,4);
                readBuffer.Slice(0,8).CopyTo(s);
                readBuffer = readBuffer.Slice(8);
                var addLength = 16;
                var encrypted = readBuffer.Slice(0,addLength).ToArray();
                readBuffer = readBuffer.Slice(addLength);
                var tag = readBuffer.ToArray();
                //sequenceNumber is skip 8
                // frametype is the next
                
                var decData = _clientKey.Decrypt(_clientNounce, encrypted,tag, additionalData);
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
