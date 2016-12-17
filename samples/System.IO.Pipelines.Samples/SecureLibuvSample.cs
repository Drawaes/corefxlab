using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Libuv;
using System.IO.Pipelines.Networking.Tls;
using System.IO.Pipelines.Networking.Tls.Managed;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Formatting;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.PlatformAbstractions;

namespace System.IO.Pipelines.Samples
{
    public class SecureLibuvSample
    {
        public static void Run()
        {
            var ip = IPAddress.Any;
            int port = 5000;
            var thread = new UvThread();
            var listener = new UvTcpListener(thread, new IPEndPoint(ip, port));
            string _certificatePath = Path.Combine(PlatformServices.Default.Application.ApplicationBasePath, "data", "TestCert.pfx");
            string _certificatePassword = "Test123t";
            var cert = new X509Certificate2(_certificatePath, _certificatePassword);
            var factory = new PipelineFactory();
            var serverContext = new ManagedSecurityContext(factory, cert);//new SecurityContext(factory,"test",true,cert);// 

            listener.OnConnection(async insecureconnection =>
            {
                using (var connection = serverContext.CreateSecurePipeline(insecureconnection))
                {
                    var httpParser = new HttpRequestParser();

                    while (true)
                    {
                        // Wait for data
                        var result = await connection.Input.ReadAsync();
                        var input = result.Buffer;

                        try
                        {
                            if (input.IsEmpty && result.IsCompleted)
                            {
                                // No more data
                                break;
                            }

                            // Parse the input http request
                            var parseResult = httpParser.ParseRequest(ref input);

                            switch (parseResult)
                            {
                                case HttpRequestParser.ParseResult.Incomplete:
                                    if (result.IsCompleted)
                                    {
                                        // Didn't get the whole request and the connection ended
                                        throw new EndOfStreamException();
                                    }
                                    // Need more data
                                    continue;
                                case HttpRequestParser.ParseResult.Complete:
                                    break;
                                case HttpRequestParser.ParseResult.BadRequest:
                                    throw new Exception();
                                default:
                                    break;
                            }

                            // Writing directly to pooled buffers
                            var output = connection.Output.Alloc();
                            var formatter = new OutputFormatter<WritableBuffer>(output, EncodingData.InvariantUtf8);
                            formatter.Append("HTTP/1.1 200 OK");
                            formatter.Append("\r\nContent-Length: 13");
                            formatter.Append("\r\nContent-Type: text/plain");
                            formatter.Append("\r\n\r\n");
                            formatter.Append("Hello, World!");
                            await output.FlushAsync();

                            httpParser.Reset();
                        }
                        finally
                        {
                            // Consume the input
                            connection.Input.Advance(input.Start, input.End);
                        }
                    }
                }
            });

            listener.StartAsync().GetAwaiter().GetResult();

            Console.WriteLine($"Listening on {ip} on port {port}");
            var wh = new ManualResetEventSlim();
            Console.CancelKeyPress += (sender, e) =>
            {
                wh.Set();
            };

            wh.Wait();

            listener.Dispose();
            thread.Dispose();
        }
    }
}
