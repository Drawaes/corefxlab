using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls
{
    public interface IStateMachine
    {
        void HandleHandshake(ReadableBuffer buffer, ref WritableBuffer writer);
        void HandleChangeCipherSpec(ReadableBuffer buffer, ref WritableBuffer writer);
        void HandleAppData(ReadableBuffer buffer, ref WritableBuffer writer);
        void HandleAlert(ReadableBuffer buff, ref WritableBuffer writer);
    }
}
