using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls;
using System.IO.Pipelines.Networking.Tls.Managed;
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
        private static readonly string _certificatePassword = "Test123t";
        //private static readonly string _shortTestString = "The quick brown fox jumped over the lazy dog.";

        [Fact]
        public Task PipelineAllTheThings()
        {
            using (var cert = new X509Certificate2(_certificatePath, _certificatePassword))
            using (var factory = new PipelineFactory())
            using (var serverContext = new ManagedSecurityContext(factory, cert))
            using (var socketClient = new Networking.Sockets.SocketListener(factory))
            using (var clientContext = new SecurityContext(factory, "test", false, null))
            {
                var ipEndPoint = new IPEndPoint(IPAddress.Parse("192.168.1.70"), 443);
                socketClient.OnConnection(s => serverContext.CreateSecurePipeline(s).PerformHandshakeAsync());
                socketClient.Start(ipEndPoint);
                Console.ReadLine();
                return Task.FromResult(0);

                //                var loopback = new LoopbackPipeline(factory);
                //                using (var server = serverContext.CreateSecurePipeline(loopback.ServerPipeline))
                //                using (var client = clientContext.CreateSecurePipeline(loopback.ClientPipeline))
                //                {
                //#pragma warning disable CS4014 // Because this call is not awaited, execution of the current method continues before the call is completed
                //                    Echo(server);
                //#pragma warning restore CS4014 // Because this call is not awaited, execution of the current method continues before the call is completed
                //                    var outputBuffer = client.Output.Alloc(_shortTestString.Length);
                //                    outputBuffer.Write(Encoding.UTF8.GetBytes(_shortTestString));
                //                    await outputBuffer.FlushAsync();

                //                    //Now check we get the same thing back
                //                    string resultString;
                //                    while (true)
                //                    {
                //                        var result = await client.Input.ReadAsync();
                //                        if (result.Buffer.Length >= _shortTestString.Length)
                //                        {
                //                            resultString = result.Buffer.GetUtf8String();
                //                            client.Input.Advance(result.Buffer.End);
                //                            break;
                //                        }
                //                        client.Input.Advance(result.Buffer.Start, result.Buffer.End);
                //                    }
                //                    Assert.Equal(_shortTestString, resultString);
                //                }
            }
        }
        
        private async Task Echo(ISecurePipeline pipeline)
        {
            await pipeline.PerformHandshakeAsync();
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
