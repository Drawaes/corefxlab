using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Certificates;
using System.IO.Pipelines.Networking.Tls.Internal;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls
{
    public class SecurePipelineListener : IDisposable
    {
        private readonly PipelineFactory _factory;
        private readonly CertificateList _certList;
        private readonly CipherList _cipherList;

        public SecurePipelineListener(PipelineFactory factory, CertificateList certList)
        {
            _cipherList = new CipherList();
            _certList = certList;
            _factory = factory;
        }

        public CipherList CipherList => _cipherList;

        public SecurePipelineConnection CreateSecurePipeline(IPipelineConnection pipeline)
        {
            return new SecurePipelineConnection(pipeline, _factory, this);
        }

        public void Dispose()
        {
        }
    }
}
