using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed
{
    public interface IMessageWriter
    {
        byte MessageType { get; }

        void WriteMessage(ref WritableBuffer buffer, ManagedConnectionContext context);
    }
}
