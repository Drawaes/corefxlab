using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.BulkCiphers;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Handshake;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.KeyExchange;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.TlsSpec;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal
{
    internal class ConnectionState
    {
        private bool _decryptingClient;
        private bool _encryptingServer;
        private Pipe _inDataPipe;
        private IPipelineWriter _outDataPipe;
        private TaskCompletionSource<bool> _clientCipherSpecChanged = new TaskCompletionSource<bool>();
        private TaskCompletionSource<bool> _keysCreated = new TaskCompletionSource<bool>();
        private Task _cipherMode;
        private CipherSuite _cipherSuite;
        private readonly CipherList _cipherList;
        private IKeyExchangeInstance _keyExchange;
        private byte[] _masterSecret;

        public ConnectionState(Pipe inDataPipe, IPipelineWriter outDataPipe, CipherList cipherList)
        {
            _cipherList = cipherList;
            _cipherMode = Task.WhenAll(_clientCipherSpecChanged.Task, _keysCreated.Task);
            _inDataPipe = inDataPipe;
            _outDataPipe = outDataPipe;
            DoHandshake();
        }

        internal byte[] ClientRandom { get;set;}
        internal byte[] ServerRandom { get;set;}
        internal IBulkCipherInstance ClientKey { get;set;}
        internal IBulkCipherInstance ServerKey { get;set;}
        internal IHashInstance HandshakeHash { get; set; }
        internal CipherList CipherList => _cipherList;
        internal IKeyExchangeInstance KeyExchange => _keyExchange;
        internal CipherSuite CipherSuite => _cipherSuite;
        internal bool EncryptingServer => _encryptingServer;
        internal int MaxContentSize => 16 * 1024 -1 - ServerKey.TrailerSize - ServerKey.ExplicitNonceSize - 5;

        private async void DoHandshake()
        {
            while (true)
            {
                var result = await _inDataPipe.ReadAsync();
                var buffer = result.Buffer;
                try
                {
                    if (buffer.IsEmpty && result.IsCompleted)
                    {
                        break;
                    }
                    ReadableBuffer messageBuffer;
                    HandshakeMessageType messageType;
                    while (TryGetHandshakeType(ref buffer, out messageBuffer, out messageType))
                    {
                        WritableBuffer writeBuffer;
                        switch (messageType)
                        {
                            case HandshakeMessageType.ClientHello:
                                Hello.ProcessClientHello(messageBuffer, this);
                                writeBuffer = _outDataPipe.Alloc();
                                Hello.WriteServerHello(ref writeBuffer, this);
                                await writeBuffer.FlushAsync();
                                writeBuffer = _outDataPipe.Alloc();
                                Handshake.Certificates.WriteCertificate(this, ref writeBuffer);
                                await writeBuffer.FlushAsync();
                                writeBuffer = _outDataPipe.Alloc();
                                _keyExchange.WriteServerKeyExchange(ref writeBuffer);
                                await writeBuffer.FlushAsync();
                                writeBuffer = _outDataPipe.Alloc();
                                Hello.WriteServerHelloDone(this, ref writeBuffer);
                                await writeBuffer.FlushAsync();
                                break;
                            case HandshakeMessageType.ClientKeyExchange:
                                _masterSecret = _keyExchange.ProcessClientKeyExchange(messageBuffer);
                                GenerateKeys();
                                _decryptingClient = true;
                                _keysCreated.SetResult(true);
                                break;
                            case HandshakeMessageType.Finished:
                                Finished.ProcessClient(messageBuffer, this, _masterSecret);
                                writeBuffer = _outDataPipe.Alloc();
                                ChangeCipherSpec.Write(this, ref writeBuffer);
                                await writeBuffer.FlushAsync();
                                _encryptingServer = true;
                                writeBuffer = _outDataPipe.Alloc();
                                Finished.WriteServer(ref writeBuffer, this, _masterSecret);
                                await writeBuffer.FlushAsync();
                                break;
                            default:
                                throw new NotImplementedException();
                        }
                    }
                }
                finally
                {
                    _inDataPipe.AdvanceReader(buffer.Start, buffer.End);
                }
            }
        }

        public void SetCipherSuite(CipherSuite suite)
        {
            _cipherSuite = suite;
            HandshakeHash = _cipherSuite.Hash.GetLongRunningHash(null);
            _keyExchange = _cipherSuite.KeyExchange.GetInstance(this);
        }
                
        private bool TryGetHandshakeType(ref ReadableBuffer buffer, out ReadableBuffer messageBuffer, out HandshakeMessageType messageType)
        {
            if (buffer.Length < 4)
            {
                messageType = HandshakeMessageType.Incomplete;
                messageBuffer = default(ReadableBuffer);
                return false;
            }
            messageType = buffer.ReadBigEndian<HandshakeMessageType>();
            ///Add check to make sure this is a valid message to recieve in this state
            var length = buffer.Slice(1).ReadBigEndian24bit();
            if (buffer.Length < (length + 4))
            {
                messageBuffer = default(ReadableBuffer);
                return false;
            }
            messageBuffer = buffer.Slice(0, length + 4);
            buffer = buffer.Slice(messageBuffer.End);
            return true;
        }

        public Task DecryptFrame(ReadableBuffer buffer, IPipelineWriter writer)
        {
            var output = writer.Alloc();
            if (_decryptingClient)
            {
               
                ClientKey.DecryptFrame(buffer, ref output);
            }
            else
            {
                output.Append(buffer.Slice(5));
            }
            return output.FlushAsync();
        }

        private unsafe void GenerateKeys()
        {
            //We have the master secret we can move on to making our keys!!!
            var seed = new byte[ClientRandom.Length + ServerRandom.Length + Tls12Utils.KeyExpansionSize];
            var seedSpan = new Span<byte>(seed);
            var seedLabel = new Span<byte>((byte*)Tls12Utils.KeyExpansionPointer, Tls12Utils.KeyExpansionSize);
            seedLabel.CopyTo(seedSpan);
            seedSpan = seedSpan.Slice(seedLabel.Length);

            var serverRandom = new Span<byte>(ServerRandom);
            serverRandom.CopyTo(seedSpan);
            seedSpan = seedSpan.Slice(serverRandom.Length);
            var clientRandom = new Span<byte>(ClientRandom);
            clientRandom.CopyTo(seedSpan);

            var keyMaterial = new byte[CipherSuite.KeyMaterialRequired];
            Tls12Utils.P_Hash12(CipherSuite.Hash, keyMaterial, _masterSecret, seed);
            CipherSuite.ProcessKeyMaterial(this, keyMaterial);
        }

        internal Task ChangeCipher()
        {
            _clientCipherSpecChanged.SetResult(true);
            return _cipherMode;
        }
    }
}
