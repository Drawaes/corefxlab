using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed
{
    internal class ConnectionState
    {
        private CipherSuite _currentSuite;
        private bool _handshakeComplete;
        private bool _changedCipherSpec;


        public void CheckForValidFrameType(TlsFrameType frameType)
        {
            switch(frameType)
            {
                case TlsFrameType.Invalid:
                case TlsFrameType.Incomplete:
                case TlsFrameType.Alert:
                    throw new InvalidOperationException("Bad frame");
                case TlsFrameType.AppData:
                    if(!_handshakeComplete)
                    {
                        throw new InvalidOperationException("Data cannot be received before we switch to encrypted mode");
                    }
                    break;
                case TlsFrameType.Handshake:
                    if(_handshakeComplete)
                    {
                        throw new InvalidOperationException("We don't support renegotiation at this time");
                    }
                    break;
                case TlsFrameType.ChangeCipherSpec:
                default:
                    throw new NotImplementedException("Get around to this!");

            }
        }

        public void DecryptRecord(ref ReadableBuffer buffer)
        {
            if(!_changedCipherSpec)
            {
                //Do nothing the buffer is just fine the way it is we aren't decrypting yet
            }

            throw new NotImplementedException("No decryption yet!");
        }

        internal Task ProcessHandshakeAsync(ReadableBuffer messageBuffer, IPipelineWriter output)
        {
            throw new NotImplementedException();
        }
    }
}
