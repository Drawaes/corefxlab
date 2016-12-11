using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Alerts
{
    public class AlertException:Exception
    {
        public AlertException(ReadableBuffer buffer)
        {

        }
    }
}
