using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Tls13
{
    public class Tls13StateMachine : IStateMachine
    {
        private TlsVersion _tlsVersion;

        public Tls13StateMachine(TlsVersion version)
        {
            _tlsVersion = version;
        }

        public void HandleAlert(ReadableBuffer buff, ref WritableBuffer writer)
        {
            throw new NotImplementedException();
        }

        public void HandleAppData(ReadableBuffer buffer, ref WritableBuffer writer)
        {
            throw new NotImplementedException();
        }

        public void HandleChangeCipherSpec(ReadableBuffer buffer, ref WritableBuffer writer)
        {
            throw new NotImplementedException();
        }

        public void HandleHandshake(ReadableBuffer buffer, ref WritableBuffer writer)
        {
            throw new NotImplementedException();
        }
    }
}
