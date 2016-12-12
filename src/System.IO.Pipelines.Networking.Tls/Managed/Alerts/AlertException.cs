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

        public AlertException(AlertDescription description, AlertServerity serverity)
        {
            Description = description;
            Serverity = serverity;
        }

        public AlertDescription Description { get; private set;}
        public AlertServerity Serverity { get; private set;}
    }
}
