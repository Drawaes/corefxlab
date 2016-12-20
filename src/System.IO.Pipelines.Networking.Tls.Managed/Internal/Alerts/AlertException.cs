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

        public AlertType AlertType { get;private set;}

        public static void ThrowAlertException(AlertType alertType)
        {
            throw new AlertException(alertType);
        }
    }
}
