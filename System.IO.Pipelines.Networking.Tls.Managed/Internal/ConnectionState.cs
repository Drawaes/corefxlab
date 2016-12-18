using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal
{
    public class ConnectionState
    {
        private bool _decryptingClient;
        private Pipe _dataPipe;

        public ConnectionState(Pipe dataPipe)
        {
            _dataPipe = dataPipe;
        }



        public Task DecryptFrame(ReadableBuffer buffer, ref IPipelineWriter writer)
        {
            if(_decryptingClient)
            {
                throw new NotImplementedException();
            }
            else
            {
                var output = writer.Alloc();
                output.Append(buffer);
                return output.FlushAsync();
            }
        }
    }
}
