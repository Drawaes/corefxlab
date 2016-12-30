using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates
{
    internal class HashAndSignRsaInstance : IHashAndSignInstance
    {
        private IHashInstance _hashInstance;
        private IHashProvider _hashProvider;
        private ICertificate _certificate;
        private PaddingType _padding;

        internal HashAndSignRsaInstance(IHashProvider hashProvider, PaddingType padding, ICertificate certificate)
        {
            _padding = padding;
            _hashInstance = hashProvider.GetLongRunningHash(null);
            _hashProvider = hashProvider;
            _certificate = certificate;
        }

        public ICertificate Certificate => _certificate;

        public int HashLength
        {
            get { return _certificate.SignatureSize; }
        }

        public void Dispose()
        {
            _hashInstance.Dispose();
        }

        public unsafe void Finish(byte* output, int length, bool completed)
        {
            _hashInstance.Finish(output, length, true);
            _certificate.SignHash(_hashProvider, output, length, output, _hashInstance.HashLength, _padding);
        }

        public unsafe void HashData(byte* buffer, int length)
        {
            _hashInstance.HashData(buffer, length);
        }
    }
}
