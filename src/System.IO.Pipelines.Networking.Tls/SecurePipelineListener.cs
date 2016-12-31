using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls
{
    public class SecurePipelineListener : IDisposable
    {
        private readonly PipelineFactory _factory;

        public SecurePipelineListener(PipelineFactory factory, X509Certificate2[] certificates)
        {
            _factory = factory;
        }

        public SecurePipelineConnection CreateSecurePipeline(IPipelineConnection pipeline)
        {
            return new SecurePipelineConnection(pipeline, _factory);
        }

        public void Dispose()
        {
        }
    }
}
