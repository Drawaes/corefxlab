using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed
{
    public class SecurePipelineListener
    {
        private ICertificate _rsaCertificate;
        private ICertificate _ecdsaCerfiticate;
        private PipelineFactory _factory;
        
        public SecurePipelineListener(PipelineFactory factory, X509Certificate2[] certificates)
        {
            if(certificates == null || certificates.Length <1)
            {
                throw new ArgumentException(nameof(certificates),"You require at least one certificate to start a server connection");
            }
            _factory = factory;
        }

        public SecurePipeline CreateSecurePipeline(IPipelineConnection pipeline)
        {
            return new SecurePipeline(pipeline, _factory, this);
        }
    }
}
