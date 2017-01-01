using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.RecordProtocol
{
    public class RecordUtils
    {
        public delegate void RecordContentWriter(ref WritableBuffer writer);
        public const int RecordHeaderLength = 5;

        public static bool TryGetFrame(ref ReadableBuffer buffer, out ReadableBuffer messageBuffer)
        {
            messageBuffer = default(ReadableBuffer);
            if (buffer.Length < 5)
            {
                return false;
            }
            var frameType = buffer.ReadBigEndian<RecordType>();
            if (frameType != RecordType.Alert && frameType != RecordType.Application
                && frameType != RecordType.ChangeCipherSpec && frameType != RecordType.Handshake)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error);
            }
            var version = buffer.Slice(1).ReadBigEndian<ushort>();
            if (version < 0x0300 || version > 0x0400)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error);
            }
            var length = buffer.Slice(3).ReadBigEndian<ushort>();
            if (buffer.Length >= (length + RecordHeaderLength))
            {
                messageBuffer = buffer.Slice(0, length + RecordHeaderLength);
                buffer = buffer.Slice(length + RecordHeaderLength);
                return true;
            }
            return false;
        }
    }
}
