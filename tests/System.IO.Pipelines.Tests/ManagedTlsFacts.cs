using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls;
using System.IO.Pipelines.Networking.Tls.Managed;
using System.IO.Pipelines.Tests.Internal;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Extensions.PlatformAbstractions;

namespace System.IO.Pipelines.Tests
{
    public class ManagedTlsFacts
    {
        private static readonly string _certificatePath = Path.Combine(PlatformServices.Default.Application.ApplicationBasePath, "data", "TestCert.pfx");
        private static readonly string _certificatePassword = "Test123t";
        private static readonly string _shortTestString = "The quick brown fox jumped over the lazy dog.";

        public async Task PipelineAllTheThings()
        {
            using (var cert = new X509Certificate2(_certificatePath, _certificatePassword))
            using (var factory = new PipelineFactory())
            using (var serverContext = new ManagedSecurityContext(factory, cert))
            using (var clientContext = new OpenSslSecurityContext(factory, "test", false, null, null))
            {
                var loopback = new LoopbackPipeline(factory);
                using (var server = serverContext.CreateSecurePipeline(loopback.ServerPipeline))
                using (var client = clientContext.CreateSecurePipeline(loopback.ClientPipeline))
                {
                    await client.PerformHandshakeAsync();
                }
            }
        }
    }
}
