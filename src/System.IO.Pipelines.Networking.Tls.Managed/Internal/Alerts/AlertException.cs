using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Alerts
{
    public class AlertException:Exception
    {
        public AlertException(AlertType alertType)
        {
            AlertType = alertType;
        }

        public AlertType AlertType { get; private set;}

        internal void WriteToOutput(ref WritableBuffer output, ConnectionState state)
        {
            var writer = new FrameWriter(ref output, TlsFrameType.Alert, state);

            output.WriteBigEndian<byte>(2);
            output.WriteBigEndian<byte>((byte)AlertType);

            writer.Finish(ref output);
        }
    }
}
