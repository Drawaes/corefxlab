using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls
{
    public class ManagedSecurityContext : IDisposable
    {
        private readonly bool _isServer;
        private readonly PipelineFactory _factory;
        private readonly X509Certificate2 _certificate;
        private IntPtr _privateKeyHandle;
        private KeyExchangeCipher _keyExchangeAlgo;
        private CipherList _cipherList;
        
        public ManagedSecurityContext(PipelineFactory factory, bool isServer, X509Certificate2 certificate)
        {
            if (isServer && certificate == null)
            {
                throw new ArgumentException("We need a certificate to load if you want to run in server mode");
            }

            _factory = factory;
            _isServer = isServer;
            _certificate = certificate;
            if (certificate != null)
            {
                _privateKeyHandle = Internal.ManagedTls.InteropCertificates.GetPrivateKeyHandle(certificate);
                _keyExchangeAlgo = (KeyExchangeCipher)Enum.Parse(typeof(KeyExchangeCipher), Internal.ManagedTls.InteropCertificates.GetPrivateKeyAlgo(_privateKeyHandle),true);
            }
            _cipherList = new CipherList();
            _cipherList.SetSupported(_keyExchangeAlgo);
        }

        public ApplicationLayerProtocolIds AlpnSupportedProtocols { get; set; }
        public bool IsServer => _isServer;
        internal X509Certificate2 Certificate => _certificate;
        internal IntPtr PrivateKeyHandle => _privateKeyHandle;
        public CipherList Ciphers => _cipherList;

        public ISecurePipeline CreateSecurePipeline(IPipelineConnection pipeline)
        {
            return new SecurePipeline<ManagedConnectionContext>(pipeline, _factory, new ManagedConnectionContext(this));
        }

        public void Dispose()
        {
            throw new NotImplementedException();
        }

        public void SetupContext()
        {

        }
    }
}
