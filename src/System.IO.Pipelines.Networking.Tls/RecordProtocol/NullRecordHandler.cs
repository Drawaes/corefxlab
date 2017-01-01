using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.RecordProtocol;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.RecordProtocol
{
    public class NullRecordHandler:IRecordHandler
    {
        public RecordType ProcessRecord(ref ReadableBuffer messageBuffer)
        {
            var recordType = messageBuffer.ReadBigEndian<RecordType>();
            if(recordType != RecordType.Handshake)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.unexpected_message);
            }
            messageBuffer = messageBuffer.Slice(RecordUtils.RecordHeaderLength);
            return recordType;
        }

        public void WriteRecord(ref WritableBuffer writeBuffer, RecordType recordType, RecordUtils.RecordContentWriter innerMethod)
        {
            throw new InvalidOperationException();
        }
    }
}
