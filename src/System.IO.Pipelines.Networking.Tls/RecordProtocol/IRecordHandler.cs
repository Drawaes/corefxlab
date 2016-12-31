using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.RecordProtocol
{
    public interface IRecordHandler
    {
        RecordType ProcessRecord(ref ReadableBuffer messageBuffer);
    }
}
