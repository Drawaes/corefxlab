using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls;
using System.IO.Pipelines.Networking.Tls.Managed;
using System.IO.Pipelines.Tests.Internal;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Extensions.PlatformAbstractions;
using Xunit;

namespace System.IO.Pipelines.Tests
{
    public class ManagedTlsFacts
    {
        private static readonly string _certificatePath = Path.Combine(PlatformServices.Default.Application.ApplicationBasePath, "data", "TestCert.pfx");
        private static readonly string _certificatePassword = "Test123t";
        //private static readonly string _shortTestString = "The quick brown fox jumped over the lazy dog.";

        [Fact]
        public Task PipelineAllTheThings()
        {
            using (var cert = new X509Certificate2(_certificatePath, _certificatePassword))
            using (var factory = new PipelineFactory())
            using (var serverContext = new ManagedSecurityContext(factory, cert))
            using (var socketClient = new Networking.Sockets.SocketListener(factory))
            using (var clientContext = new OpenSslSecurityContext(factory, "test", false, null, null))
            {
                var ipEndPoint = new IPEndPoint(IPAddress.Loopback, 443);
                socketClient.OnConnection(s => serverContext.CreateSecurePipeline(s).PerformHandshakeAsync());
                socketClient.Start(ipEndPoint);
                Console.ReadLine();
                return Task.FromResult(0);

                //var loopback = new LoopbackPipeline(factory);
                //using (var server = serverContext.CreateSecurePipeline(loopback.ServerPipeline))
                //using (var client = clientContext.CreateSecurePipeline(loopback.ClientPipeline))
                //{
                //    return client.PerformHandshakeAsync();
                //}
            }
        }
    }
}
