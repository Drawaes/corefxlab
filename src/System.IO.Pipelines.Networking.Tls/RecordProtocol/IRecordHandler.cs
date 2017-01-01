using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using static System.IO.Pipelines.Networking.Tls.RecordProtocol.RecordUtils;

namespace System.IO.Pipelines.Networking.Tls.RecordProtocol
{
    public interface IRecordHandler
    {
        RecordType ProcessRecord(ref ReadableBuffer messageBuffer);
        void WriteRecord(ref WritableBuffer writeBuffer, RecordType recordType, RecordContentWriter innerMethod);
    }
}
