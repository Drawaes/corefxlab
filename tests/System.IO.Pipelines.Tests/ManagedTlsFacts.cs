using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls;
using System.IO.Pipelines.Networking.Tls.Certificates;
using System.IO.Pipelines.Tests.Internal;
using System.IO.Pipelines.Text.Primitives;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.PlatformAbstractions;
using Xunit;

namespace System.IO.Pipelines.Tests
{
    public class ManagedTlsFacts
    {
        private static readonly string _certificatePath = Path.Combine(PlatformServices.Default.Application.ApplicationBasePath, "data", "TestCert.pfx");
        private static readonly string _ecdsaCertificate = Path.Combine(PlatformServices.Default.Application.ApplicationBasePath,"data", "certificate.pfx");
        private static readonly string _certificatePassword = "Test123t";
        //private static readonly string _shortTestString = "The quick brown fox jumped over the lazy dog.";

        [Fact]
        public Task PipelineAllTheThings()
        {
            using (var cert = new X509Certificate2(_certificatePath, _certificatePassword, X509KeyStorageFlags.Exportable))
            using (var cert2 = new X509Certificate2(_ecdsaCertificate, _certificatePassword,X509KeyStorageFlags.Exportable))
            {
                var certList = new CertificateList(cert2,cert);
                using (var factory = new PipelineFactory())
                using (var serverContext = new SecurePipelineListener(factory, certList))
                using (var socketClient = new Networking.Sockets.SocketListener(factory))
                {
                    var ipEndPoint = new IPEndPoint(IPAddress.Parse("192.168.1.70"), 443);
                    socketClient.OnConnection(async s =>
                    {
                        var sp = serverContext.CreateSecurePipeline(s);
                        await Echo(sp);
                    });
                    socketClient.Start(ipEndPoint);
                    Console.ReadLine();
                    return Task.FromResult(0);
                }
            }
        }

        private async Task Echo(SecurePipelineConnection pipeline)
        {
            try
            {
                while (true)
                {
                    var result = await pipeline.Input.ReadAsync();
                    var request = result.Buffer;

                    if (request.IsEmpty && result.IsCompleted)
                    {
                        pipeline.Input.Advance(request.End);
                        break;
                    }
                    int len = request.Length;
                    var response = pipeline.Output.Alloc();
                    response.Append(request);
                    await response.FlushAsync();
                    pipeline.Input.Advance(request.End);
                }
                pipeline.Input.Complete();
                pipeline.Output.Complete();
            }
            catch (Exception ex)
            {
                pipeline.Input.Complete(ex);
                pipeline.Output.Complete(ex);
            }
        }
    }
}