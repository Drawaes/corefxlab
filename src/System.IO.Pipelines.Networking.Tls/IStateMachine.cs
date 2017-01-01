using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Hashes;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls
{
    public interface IStateMachine
    {
        void HandleRecord(RecordProtocol.RecordType recordType, ReadableBuffer buffer, ref WritableBuffer writer);
        IHashInstance HandshakeHash { get;}
    }
}
