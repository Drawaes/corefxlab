using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates.Windows;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed
{
    public class SecurePipelineListener:IDisposable
    {
        private ICertificatePal _certificateFactory;
        private PipelineFactory _factory;
        private readonly CipherList _cipherList;

        public SecurePipelineListener(PipelineFactory factory, X509Certificate2[] certificates)
        {
            if(certificates == null || certificates.Length <1)
            {
                throw new ArgumentException(nameof(certificates),"You require at least one certificate to start a server connection");
            }
            _factory = factory;

            if(RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                _certificateFactory = new WindowsCertificatePal();
            }
            else
            {
                throw new NotImplementedException();
            }
            _certificateFactory.LoadCertificates(certificates); 
            _cipherList = new CipherList(_certificateFactory);
        }

        internal CipherList CipherList => _cipherList;

        public SecurePipeline CreateSecurePipeline(IPipelineConnection pipeline)
        {
            return new SecurePipeline(pipeline, _factory, this);
        }

        public void Dispose()
        {
        }
    }
}
