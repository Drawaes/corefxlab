using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Alerts
{
    public class AlertDescription
    {
        public static readonly AlertDescription[] Descriptions = new AlertDescription[120];

        static AlertDescription()
        {
            Descriptions[0] = new AlertDescription() { Code = 0, Description = "Close notify", Serverity = AlertServerity.Fatal };
            Descriptions[10] = new AlertDescription() { Code = 10, Description = "Unexpected message", Serverity = AlertServerity.Fatal };
            Descriptions[20] = new AlertDescription() { Code = 20, Description = "Bad record MAC", Serverity = AlertServerity.Fatal };
            Descriptions[21] = new AlertDescription() { Code = 21, Description = "Decryption failed", Serverity = AlertServerity.Fatal };
            Descriptions[22] = new AlertDescription() { Code = 22, Description = "Record overflow", Serverity = AlertServerity.Fatal };
            Descriptions[30] = new AlertDescription() { Code = 30, Description = "Decompression failure", Serverity = AlertServerity.Fatal };
            Descriptions[40] = new AlertDescription() { Code = 40, Description = "Handshake failure", Serverity = AlertServerity.Fatal };
            Descriptions[41] = new AlertDescription() { Code = 41, Description = "No certificate", Serverity = AlertServerity.Fatal };
            Descriptions[42] = new AlertDescription() { Code = 42, Description = "Bad certificate", Serverity = AlertServerity.Fatal };
            Descriptions[43] = new AlertDescription() { Code = 43, Description = "Unsupported certificate", Serverity = AlertServerity.Fatal };
            Descriptions[44] = new AlertDescription() { Code = 44, Description = "Certificate revoked", Serverity = AlertServerity.Fatal };
            Descriptions[45] = new AlertDescription() { Code = 45, Description = "Certificate expired", Serverity = AlertServerity.Fatal };
            Descriptions[46] = new AlertDescription() { Code = 46, Description = "Certificate unknown", Serverity = AlertServerity.Fatal };
            Descriptions[47] = new AlertDescription() { Code = 47, Description = "Illegal parameter", Serverity = AlertServerity.Fatal };
            Descriptions[48] = new AlertDescription() { Code = 48, Description = "Unknown CA(Certificate authority)", Serverity = AlertServerity.Fatal };
            Descriptions[49] = new AlertDescription() { Code = 49, Description = "Access denied", Serverity = AlertServerity.Fatal };
            Descriptions[50] = new AlertDescription() { Code = 50, Description = "Decode error", Serverity = AlertServerity.Fatal };
            Descriptions[51] = new AlertDescription() { Code = 51, Description = "Decrypt error", Serverity = AlertServerity.Fatal };
            Descriptions[60] = new AlertDescription() { Code = 60, Description = "Export restriction", Serverity = AlertServerity.Fatal };
            Descriptions[70] = new AlertDescription() { Code = 70, Description = "Protocol version", Serverity = AlertServerity.Fatal };
            Descriptions[71] = new AlertDescription() { Code = 71, Description = "Insufficient security", Serverity = AlertServerity.Fatal };
            Descriptions[80] = new AlertDescription() { Code = 80, Description = "Internal error  fatal", Serverity = AlertServerity.Fatal };
            Descriptions[86] = new AlertDescription() { Code = 86, Description = "Inappropriate Fallback", Serverity = AlertServerity.Fatal };
            Descriptions[90] = new AlertDescription() { Code = 90, Description = "User canceled", Serverity = AlertServerity.Fatal };
            Descriptions[100] = new AlertDescription() { Code = 100, Description = "No renegotiation", Serverity = AlertServerity.Fatal };
            Descriptions[110] = new AlertDescription() { Code = 110, Description = "Unsupported extension", Serverity = AlertServerity.Fatal };
            Descriptions[111] = new AlertDescription() { Code = 111, Description = "Certificate unobtainable", Serverity = AlertServerity.Fatal };
            Descriptions[112] = new AlertDescription() { Code = 112, Description = "Unrecognized name", Serverity = AlertServerity.Fatal };
            Descriptions[113] = new AlertDescription() { Code = 113, Description = "Bad certificate status response", Serverity = AlertServerity.Fatal };
            Descriptions[114] = new AlertDescription() { Code = 114, Description = "Bad certificate hash value", Serverity = AlertServerity.Fatal };
            Descriptions[115] = new AlertDescription() { Code = 115, Description = "Unknown PSK identity(used in TLS - PSK and TLS - SRP)", Serverity = AlertServerity.Fatal };
            Descriptions[120] = new AlertDescription() { Code = 120, Description = "No Application Protocol", Serverity = AlertServerity.Fatal };
        }

        public byte Code { get; private set; }
        public string Description { get; private set; }
        public AlertServerity Serverity { get; private set; }
    }
}
