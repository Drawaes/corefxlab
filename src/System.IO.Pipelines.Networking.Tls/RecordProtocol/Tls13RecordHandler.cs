using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.RecordProtocol
{
    public class Tls13RecordHandler : IRecordHandler
    {
        public RecordType ProcessRecord(ref ReadableBuffer messageBuffer)
        {
            throw new NotImplementedException();
        }
    }
}
