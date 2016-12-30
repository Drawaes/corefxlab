using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates.Unix;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates.Windows;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Unix;
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

        public unsafe SecurePipelineListener(PipelineFactory factory, X509Certificate2[] certificates)
        {
            //var prov = new Internal.Hash.Windows.HashProvider(Internal.Hash.HashType.SHA256);
            //var IKM = new byte[] { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };
            //var salt = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };
            //var info = new byte[] { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9 };
            //var len = prov.HashLength;

            //var prk = new byte[len];

            //fixed (byte* p = prk)
            //fixed (byte* s = salt)
            //fixed (byte* i = IKM)
            //{
            //    prov.HmacValue(p, len, s, salt.Length, i, IKM.Length);
            //}


            if (certificates == null || certificates.Length <1)
            {
                throw new ArgumentException(nameof(certificates),"You require at least one certificate to start a server connection");
            }
            _factory = factory;

            //if(RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            //{
            //    _certificateFactory = new WindowsCertificatePal();
            //}
            //else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            //{
                OpenSslPal.Init();
                _certificateFactory = new UnixCertificatePal();
            //}
            //else
            //{
            //    throw new NotImplementedException();
            //}
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
