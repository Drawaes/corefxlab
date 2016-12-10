using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed;
using System.IO.Pipelines.Networking.Tls.Managed.BulkCiphers;
using System.IO.Pipelines.Networking.Tls.Managed.Handshake;
using System.IO.Pipelines.Networking.Tls.Managed.Hash;
using System.IO.Pipelines.Networking.Tls.Managed.KeyExchange;
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
        private bool _clientDataEncrypted;
        private bool _serverDataEncrypted;
        private byte[] _seedBuffer = new byte[s_masterSecretLabel.Length + RandomLength * 2];
        private ulong _clientSequenceNumber = 0;
        private ulong _serverSequenceNumber = 0;
        private CipherSuite _cipherSuite;
        private HashInstance _clientFinishedHash;
        private HashInstance _serverFinishedHash;
        private byte[] _clientNounce;
        private byte[] _serverNounce;
        private BulkCipherKey _clientKey;
        private BulkCipherKey _serverKey;
        private byte[] _masterSecret;
        private IKeyExchangeInstance _keyExchangeInstance;
        private static readonly TlsRecordWriter<HandshakeMessageWriter<HandshakeServerHelloWriter>> _handshakeServerHelloWriter = new TlsRecordWriter<HandshakeMessageWriter<HandshakeServerHelloWriter>>();
        private static readonly TlsRecordWriter<HandshakeMessageWriter<HandshakeServerCertificateWriter>> _handshakeCertificateWriter = new TlsRecordWriter<HandshakeMessageWriter<HandshakeServerCertificateWriter>>();
        private static readonly TlsRecordWriter<HandshakeMessageWriter<HandshakeServerHelloDone>> _handshakeServerDoneWriter = new TlsRecordWriter<HandshakeMessageWriter<HandshakeServerHelloDone>>();
        private static readonly TlsRecordWriter<ChangeCipherSpec> _changeCipherSpecWriter = new TlsRecordWriter<ChangeCipherSpec>();
        private static readonly TlsRecordWriter<HandshakeMessageWriter<HandshakeServerFinishedWriter>> _handshakeFinishedWriter = new TlsRecordWriter<HandshakeMessageWriter<HandshakeServerFinishedWriter>>();
        internal static readonly byte[] s_masterSecretLabel = Encoding.ASCII.GetBytes("master secret");
        internal static readonly byte[] s_keyexpansionLabel = Encoding.ASCII.GetBytes("key expansion");
        internal static readonly byte[] s_clientfinishedLabel = Encoding.ASCII.GetBytes("client finished");
        internal static readonly byte[] s_serverfinishedLabel = Encoding.ASCII.GetBytes("server finished");
        private static readonly Task _cachedTask = Task.FromResult(0);

        public ManagedConnectionContext(ManagedSecurityContext context)
        {
            _context = context;
            Buffer.BlockCopy(s_masterSecretLabel,0,_seedBuffer,0,s_masterSecretLabel.Length);
        }

        public int HeaderSize { get; set; }
        public bool IsServer => _context.IsServer;
        public ApplicationLayerProtocolIds NegotiatedProtocol { get ; internal set; }
        public bool ReadyToSend { get ; internal set; }
        public int TrailerSize { get; set; }
        public CipherSuite CipherSuite => _cipherSuite;
        public ManagedSecurityContext SecurityContext => _context;
        public HashInstance ClientFinishedHash => _clientFinishedHash;
        public HashInstance ServerFinishedHash => _serverFinishedHash;
        public byte[] SeedBuffer => _seedBuffer;
        public bool ServerDataEncrypted => _serverDataEncrypted;
        public BulkCipherKey ServerKey => _serverKey;
        public int MaxBlockSize => 1024 * 16 - 1;
        internal byte[] MasterSecret => _masterSecret;
        public IKeyExchangeInstance KeyExchangeInstance => _keyExchangeInstance;
        internal Span<byte> ClientRandom => new Span<byte>(_seedBuffer, s_masterSecretLabel.Length);

        public Task DecryptAsync(ReadableBuffer encryptedData, IPipelineWriter decryptedPipeline)
        {
            var sequence = GetClientSequenceNumber();
            _clientKey.DecryptFrame(ref encryptedData, sequence, _clientNounce);
            var writeBuffer = decryptedPipeline.Alloc();
            writeBuffer.Append(encryptedData.Slice(5));
            return writeBuffer.FlushAsync();
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

        internal ulong GetClientSequenceNumber()
        {
            ulong current = _clientSequenceNumber;
            _clientSequenceNumber ++;
            return current;
        }

        public Task EncryptAsync(ReadableBuffer unencryptedData, IPipelineWriter encryptedPipeline)
        {
            var buffer = encryptedPipeline.Alloc();

            _serverKey.EncryptFrame(unencryptedData, ref buffer, TlsFrameType.AppData, GetServerSequenceNumber(), _serverNounce);

            return buffer.FlushAsync();
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
            _serverFinishedHash = info.Hash.GetLongRunningHash();
            _clientFinishedHash = info.Hash.GetLongRunningHash();
            _keyExchangeInstance = info.KeyExchange.GetInstance(this);
            _cipherSuite = info;
        }

        public Task ProcessContextMessageAsync(ReadableBuffer readBuffer, IPipelineWriter writer)
        {
            if(_clientDataEncrypted)
            {
                var sequence = GetClientSequenceNumber();
                _clientKey.DecryptFrame(ref readBuffer, sequence, _clientNounce);
            }
            var frameType = (TlsFrameType)readBuffer.ReadBigEndian<byte>();
            readBuffer = readBuffer.Slice(1);
            var versionMajor = readBuffer.ReadBigEndian<byte>();
            readBuffer = readBuffer.Slice(1);
            var versionMinor = readBuffer.ReadBigEndian<byte>();
            readBuffer = readBuffer.Slice(1);
            var size = readBuffer.ReadBigEndian<ushort>();
            readBuffer = readBuffer.Slice(2);

            if (frameType == TlsFrameType.ChangeCipherSpec)
            {
                _clientDataEncrypted = true;
                return _cachedTask;
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
                    _keyExchangeInstance.WriteServerKeyExchange(ref writeBuffer);
                    writeBuffer.Commit();
                    writeBuffer = writer.Alloc();
                    _handshakeServerDoneWriter.WriteMessage(ref writeBuffer, this);
                    return writeBuffer.FlushAsync();
                case HandshakeMessageType.ClientKeyExchange:
                    ClientKeyExchange.ProcessClientKeyExchange(readBuffer, this);
                    return _cachedTask;
                case HandshakeMessageType.Finished:
                    ClientFinished.ProcessClientFinished(readBuffer, this);
                    writeBuffer = writer.Alloc();
                    _changeCipherSpecWriter.WriteMessage(ref writeBuffer, this);
                    writeBuffer.Commit();
                    _serverDataEncrypted = true;
                    writeBuffer = writer.Alloc();
                    _handshakeFinishedWriter.WriteMessage(ref writeBuffer, this);
                    return writeBuffer.FlushAsync();
            }
            throw new NotImplementedException();
        }

        public void Dispose()
        {
            _serverFinishedHash.Dispose();
            _clientFinishedHash.Dispose();
        }
    }
}
