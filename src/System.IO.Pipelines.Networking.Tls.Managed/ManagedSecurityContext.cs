using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Windows;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed
{
    public class ManagedSecurityContext:IDisposable
    {
        private IntPtr _privateKeyHandle;
        private ICertificate _certificate;
        private PipelineFactory _factory;
        private CipherList _cipherList;

        public ManagedSecurityContext(PipelineFactory factory, X509Certificate2 certificate)
            :this(factory, certificate,ApplicationLayerProtocolIds.None)
        {

        }

        public ManagedSecurityContext(PipelineFactory factory, X509Certificate2 certificate, ApplicationLayerProtocolIds alpnSupportedProtocols)
        {
            if (certificate == null)
            {
                throw new ArgumentException("We need a certificate to load if you want to run in server mode");
            }
            _factory = factory;
            _certificate = (new CertificateFactory()).GetCertificate(certificate);
            AlpnSupportedProtocols = alpnSupportedProtocols;
            _cipherList = new CipherList(_certificate);
        }

        internal ICertificate Certificate => _certificate;
        internal CipherList CipherList => _cipherList;
        public ApplicationLayerProtocolIds AlpnSupportedProtocols { get; internal set; }
        
        public SecureManagedPipeline CreateSecurePipeline(IPipelineConnection pipeline)
        {
            return new SecureManagedPipeline(pipeline, _factory, this);
        }

        public void Dispose()
        {
            _cipherList.Dispose();
        }
    }
}
