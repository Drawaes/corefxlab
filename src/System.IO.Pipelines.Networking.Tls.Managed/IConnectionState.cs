using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.BulkCiphers;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Handshake;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.TlsSpec;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed
{
    internal interface IConnectionState
    {
        Task DecryptFrame(ReadableBuffer buffer, IPipelineWriter writer);
        Task ChangeCipher();
        bool EncryptingServer { get; }
        int MaxContentSize { get; }
        CipherSuite CipherSuite { get; }
        IBulkCipherInstance ClientKey { get; }
        IBulkCipherInstance ServerKey { get; }
        IHashInstance HandshakeHash { get; }
        byte[] ClientRandom { set; get; }
        byte[] ServerRandom { get; set; }
        void ProcessExtension(ExtensionType extensionType, ReadableBuffer buffer);
        bool TrySetCipherSuite(ushort cipherSuite);
        TlsVersions TlsVersion { get;}
        void ProcessHandshakeMessage(ReadableBuffer messageBuffer, HandshakeMessageType messageType, ref WritableBuffer outBuffer);
    }
}
