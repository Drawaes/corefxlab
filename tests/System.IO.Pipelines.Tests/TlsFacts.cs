using System;
using System.Buffers;
using System.Collections.Generic;
using System.Globalization;
using System.IO.Pipelines.Networking.Tls;
using System.IO.Pipelines.Tests.Internal;
using System.IO.Pipelines.Text.Primitives;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.PlatformAbstractions;
using Xunit;

namespace System.IO.Pipelines.Tests
{
#pragma warning disable CS4014 // Because this call is not awaited, execution of the current method continues before the call is completed
    public class TlsFacts
    {
        private static readonly string _certificatePath = Path.Combine(PlatformServices.Default.Application.ApplicationBasePath, "data", "TestCert.pfx");
        private static readonly string _certificatePassword = "Test123t";
        private static readonly string _shortTestString = "The quick brown fox jumped over the lazy dog.";

        [Fact]
        public void TestAESGCM()
        {
            //NIST Test Vector 4
            //var keyString = "feffe9928665731c6d6a8f9467308308";
            //var plainTextString = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
            //var authDataString = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
            //var ivString = "cafebabefacedbaddecaf888";
            //var cipherString = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091";
            //var tagString = "5bc94fbc3221a5db94fae95ae7121a47";
            var keyString = "6E-D8-4B-03-B6-33-10-D8-FA-0A-FD-DF-20-53-8E-CE-A7-77-DB-E3-07-30-C4-8D-9B-5D-7F-1F-FA-82-81-66";
            var plainTextString = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
            var authDataString = "00-00-00-00-00-00-00-00-16-03-03-00-10";
            var ivString = "FA-6A-22-60-D5-00-B8-76-FC-E8-F2-59";
            var cipherString = "01-A3-76-F3-2F-A4-03-C8-F4-1E-22-F7-8A-B6-B2-28";
            var tagString = "56-51-C0-EC-3F-DE-10-BE-AF-41-F1-81-55-07-08-B4";

            var key = ConvertHexStringToByteArray(keyString);
            var iv = ConvertHexStringToByteArray(ivString);

            var add = ConvertHexStringToByteArray(authDataString);
            var plainText = ConvertHexStringToByteArray(plainTextString);
            var cipherText = ConvertHexStringToByteArray(cipherString);
            var authTag = ConvertHexStringToByteArray(tagString);

            var providerName = "AES_128_GCM";
            var provider = new Networking.Tls.Managed.BulkCiphers.BulkCipherProvider(providerName);
            var bufferPool = new NativeBufferPool(provider.BufferSizeNeededForState);
            provider.SetBufferPool(bufferPool);
            var keyHandle = provider.GetCipherKey(key);
            //byte[] authTagResult;
            //var result = keyHandle.Encrypt(iv, plainText, add, out authTagResult);
            //if (!result.SequenceEqual(cipherText))
            //{
            //    throw new NotImplementedException();
            //}
            var decryptedData = keyHandle.Decrypt(iv, cipherText, authTag, add);

            if (!decryptedData.SequenceEqual(plainText))
            {
                throw new InvalidOperationException();
            }

            

            //    sb.AppendLine(BitConverter.ToString(new byte[] { cipherText[i],result[i]}));
            //}
            //sb.AppendLine("--------------------------------------------- Auth Tag---------------------");
            //for(int i = 0; i < authTag.Length; i++)
            //{
            //    sb.AppendLine(BitConverter.ToString(new byte[] { authTag[i], authTagResult[i]}));
            //}
            //File.WriteAllText("C:\\Code\\compare.txt",sb.ToString());
        }

        public static byte[] ConvertHexStringToByteArray(string hexString)
        {
            hexString = hexString.Replace("-",string.Empty);
            if (hexString.Length % 2 != 0)
            {
                throw new ArgumentException(String.Format(CultureInfo.InvariantCulture, "The binary key cannot have an odd number of digits: {0}", hexString));
            }

            byte[] HexAsBytes = new byte[hexString.Length / 2];
            for (int index = 0; index < HexAsBytes.Length; index++)
            {
                string byteValue = hexString.Substring(index * 2, 2);
                HexAsBytes[index] = byte.Parse(byteValue, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            }

            return HexAsBytes;
        }

        [Fact]
        public async Task TestManagedProvider()
        {
            using (var cert = new X509Certificate2(_certificatePath, _certificatePassword, X509KeyStorageFlags.Exportable))
            using (var factory = new PipelineFactory())
            using (var socketClient = new Networking.Sockets.SocketListener(factory))
            using (var context = new ManagedSecurityContext(factory, true, cert))
            using (var clientContext = new OpenSslSecurityContext(factory, "test", false, _certificatePath, _certificatePassword))
            {
                var loopback = new LoopbackPipeline(factory);

                //var ipEndPoint = new IPEndPoint(IPAddress.Loopback, 443);
                //socketClient.OnConnection(s => context.CreateSecurePipeline(s).PerformHandshakeAsync());
                //socketClient.Start(ipEndPoint);
                using (var server = context.CreateSecurePipeline(loopback.ServerPipeline))
                using (var client = clientContext.CreateSecurePipeline(loopback.ClientPipeline))
                {


                    Echo(server);
                    client.PerformHandshakeAsync().Wait();
                    var outputBuffer = client.Output.Alloc();
                    outputBuffer.Write(Encoding.UTF8.GetBytes(_shortTestString));
                    await outputBuffer.FlushAsync();
                }
            }
        }

        [WindowsOnlyFact]
        public async Task SspiAplnMatchingProtocol()
        {
            using (var cert = new X509Certificate(_certificatePath, _certificatePassword))
            using (var factory = new PipelineFactory())
            using (var serverContext = new SecurityContext(factory, "CARoot", true, cert, ApplicationLayerProtocolIds.Http11 | ApplicationLayerProtocolIds.Http2OverTls))
            using (var clientContext = new SecurityContext(factory, "CARoot", false, null, ApplicationLayerProtocolIds.Http2OverTls))
            {
                var loopback = new LoopbackPipeline(factory);
                using (var server = serverContext.CreateSecurePipeline(loopback.ServerPipeline))
                using (var client = clientContext.CreateSecurePipeline(loopback.ClientPipeline))
                {
                    Echo(server);
                    var proto = await client.PerformHandshakeAsync();
                    Assert.Equal(ApplicationLayerProtocolIds.Http2OverTls, proto);
                }
            }
        }

        [NotWindowsFact]
        public async Task OpenSslPipelineAllTheThings()
        {
            using (var factory = new PipelineFactory())
            using (var serverContext = new OpenSslSecurityContext(factory, "test", true, _certificatePath, _certificatePassword))
            using (var clientContext = new OpenSslSecurityContext(factory, "test", false, null, null))
            {
                var loopback = new LoopbackPipeline(factory);
                using (var server = serverContext.CreateSecurePipeline(loopback.ServerPipeline))
                using (var client = clientContext.CreateSecurePipeline(loopback.ClientPipeline))
                {
                    Echo(server);
                    await client.PerformHandshakeAsync();
                    var outputBuffer = client.Output.Alloc();
                    outputBuffer.Write(Encoding.UTF8.GetBytes(_shortTestString));
                    await outputBuffer.FlushAsync();

                    //Now check we get the same thing back
                    string resultString;
                    while (true)
                    {
                        var result = await client.Input.ReadAsync();
                        if (result.Buffer.Length >= _shortTestString.Length)
                        {
                            resultString = result.Buffer.GetUtf8String();
                            client.Input.Advance(result.Buffer.End);
                            break;
                        }
                        client.Input.Advance(result.Buffer.Start, result.Buffer.End);
                    }
                    Assert.Equal(_shortTestString, resultString);
                }
            }
        }

        [WindowsOnlyFact]
        public async Task SspiPipelineAllThings()
        {
            using (var cert = new X509Certificate(_certificatePath, _certificatePassword))
            using (var factory = new PipelineFactory())
            using (var serverContext = new SecurityContext(factory, "CARoot", true, cert))
            using (var clientContext = new SecurityContext(factory, "CARoot", false, null))
            {
                var loopback = new LoopbackPipeline(factory);
                using (var server = serverContext.CreateSecurePipeline(loopback.ServerPipeline))
                using (var client = clientContext.CreateSecurePipeline(loopback.ClientPipeline))
                {
                    Echo(server);

                    await client.PerformHandshakeAsync();
                    var outputBuffer = client.Output.Alloc();
                    outputBuffer.Write(Encoding.UTF8.GetBytes(_shortTestString));
                    await outputBuffer.FlushAsync();

                    //Now check we get the same thing back
                    string resultString;
                    while (true)
                    {
                        var result = await client.Input.ReadAsync();
                        if (result.Buffer.Length >= _shortTestString.Length)
                        {
                            resultString = result.Buffer.GetUtf8String();
                            client.Input.Advance(result.Buffer.End);
                            break;
                        }
                        client.Input.Advance(result.Buffer.Start, result.Buffer.End);
                    }
                    Assert.Equal(_shortTestString, resultString);
                }
            }
        }

        [WindowsOnlyFact()]
        public async Task SspiPipelineServerStreamClient()
        {
            using (var pipelineFactory = new PipelineFactory())
            using (var cert = new X509Certificate(_certificatePath, _certificatePassword))
            using (var secContext = new SecurityContext(pipelineFactory, "CARoot", true, cert))
            {
                var loopback = new LoopbackPipeline(pipelineFactory);
                using (var server = secContext.CreateSecurePipeline(loopback.ServerPipeline))
                using (var sslStream = new SslStream(loopback.ClientPipeline.GetStream(), false, ValidateServerCertificate, null, EncryptionPolicy.RequireEncryption))
                {
                    Echo(server);

                    await sslStream.AuthenticateAsClientAsync("CARoot");

                    byte[] messsage = Encoding.UTF8.GetBytes(_shortTestString);
                    sslStream.Write(messsage);
                    sslStream.Flush();
                    // Read message from the server.
                    string serverMessage = ReadMessageFromStream(sslStream);
                    Assert.Equal(_shortTestString, serverMessage);
                }
            }
        }

        [WindowsOnlyFact()]
        public async Task SspiStreamServerPipelineClient()
        {
            using (var cert = new X509Certificate(_certificatePath, _certificatePassword))
            using (var factory = new PipelineFactory())
            using (var clientContext = new SecurityContext(factory, "CARoot", false, null))
            {
                var loopback = new LoopbackPipeline(factory);
                using (var client = clientContext.CreateSecurePipeline(loopback.ClientPipeline))
                using (var secureServer = new SslStream(loopback.ServerPipeline.GetStream(), false))
                {
                    secureServer.AuthenticateAsServerAsync(cert, false, System.Security.Authentication.SslProtocols.Tls, false);

                    await client.PerformHandshakeAsync();

                    var buff = client.Output.Alloc();
                    buff.Write(Encoding.UTF8.GetBytes(_shortTestString));
                    await buff.FlushAsync();

                    //Check that the server actually got it
                    var tempBuff = new byte[_shortTestString.Length];
                    int totalRead = 0;
                    while (true)
                    {
                        int numberOfBytes = secureServer.Read(tempBuff, totalRead, _shortTestString.Length - totalRead);
                        if (numberOfBytes == -1)
                        {
                            break;
                        }
                        totalRead += numberOfBytes;
                        if (totalRead >= _shortTestString.Length)
                        {
                            break;
                        }
                    }
                    Assert.Equal(_shortTestString, UTF8Encoding.UTF8.GetString(tempBuff));
                }
            }
        }

        [NotWindowsFact]
        public async Task OpenSslPipelineServerStreamClient()
        {
            using (var pipelineFactory = new PipelineFactory())
            using (var cert = new X509Certificate(_certificatePath, _certificatePassword))
            using (var secContext = new OpenSslSecurityContext(pipelineFactory, "CARoot", true, _certificatePath, _certificatePassword))
            {
                var loopback = new LoopbackPipeline(pipelineFactory);
                using (var server = secContext.CreateSecurePipeline(loopback.ServerPipeline))
                using (var sslStream = new SslStream(loopback.ClientPipeline.GetStream(), false, ValidateServerCertificate, null, EncryptionPolicy.RequireEncryption))
                {
                    Echo(server);
                    await sslStream.AuthenticateAsClientAsync("CARoot");
                    byte[] messsage = Encoding.UTF8.GetBytes(_shortTestString);
                    sslStream.Write(messsage);
                    sslStream.Flush();
                    // Read message from the server.
                    string serverMessage = ReadMessageFromStream(sslStream);
                    Assert.Equal(_shortTestString, serverMessage);
                }
            }
        }

        [NotWindowsFact]
        public async Task OpenSslStreamServerPipelineClient()
        {
            using (var cert = new X509Certificate(_certificatePath, _certificatePassword))
            using (var pipelineFactory = new PipelineFactory())
            using (var clientContext = new OpenSslSecurityContext(pipelineFactory, "CARoot", false, _certificatePath, _certificatePassword))
            {
                var loopback = new LoopbackPipeline(pipelineFactory);
                using (var secureServer = new SslStream(loopback.ServerPipeline.GetStream(), false))
                using (var client = clientContext.CreateSecurePipeline(loopback.ClientPipeline))
                {
                    secureServer.AuthenticateAsServerAsync(cert, false, System.Security.Authentication.SslProtocols.Tls, false);

                    await client.PerformHandshakeAsync();
                    var buff = client.Output.Alloc();
                    buff.Write(Encoding.UTF8.GetBytes(_shortTestString));
                    await buff.FlushAsync();

                    //Check that the server actually got it
                    var tempBuff = new byte[_shortTestString.Length];
                    int totalRead = 0;
                    while (true)
                    {
                        int numberOfBytes = secureServer.Read(tempBuff, totalRead, _shortTestString.Length - totalRead);
                        if (numberOfBytes == -1)
                        {
                            break;
                        }
                        totalRead += numberOfBytes;
                        if (totalRead >= _shortTestString.Length)
                        {
                            break;
                        }
                    }
                    Assert.Equal(_shortTestString, UTF8Encoding.UTF8.GetString(tempBuff));
                }
            }
        }

        private string ReadMessageFromStream(SslStream sslStream)
        {
            byte[] buffer = new byte[2048];
            StringBuilder messageData = new StringBuilder();
            int bytes = -1;
            do
            {
                bytes = sslStream.Read(buffer, 0, buffer.Length);
                Decoder decoder = Encoding.UTF8.GetDecoder();
                char[] chars = new char[decoder.GetCharCount(buffer, 0, bytes)];
                decoder.GetChars(buffer, 0, bytes, chars, 0);
                messageData.Append(chars);
                if (messageData.Length == _shortTestString.Length)
                {
                    break;
                }
            } while (bytes != 0);

            return messageData.ToString();
        }

        public bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None || sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors)
            {
                return true;
            }
            return false;
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
#pragma warning restore CS4014 // Because this call is not awaited, execution of the current method continues before the call is completed
}
