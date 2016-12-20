using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Alerts
{
    public enum AlertType : byte
    {
        Close_Notify = 0,
        Unexpected_Message = 10,
        Bad_Record_Max = 20,
        Decryption_Failed = 21,
        Record_Overflow = 22,
        Decompression_Failure = 30,
        Handshake_Failure = 40,
        No_Certificate = 41,
        Bad_Certificate = 42,
        Unsupported_Certificate = 43,
        Certificate_Revoked = 44,
        Certificate_Expired = 45,
        Certificate_Unknown = 46,
        Illegal_Parameter = 47,
        Unknown_CA = 48,
        Access_Denied = 49,
        Decode_Error = 50,
        Decrypt_Error = 51,
        Export_Restriction = 60,
        Protocol_Version = 70,
        Insufficient_Security = 71,
        Internal_Error = 80,
        Inappropriate_Fallback = 86,
        User_Canceled = 90,
        No_Renegotiation = 100,
        Unsupported_Extension = 110,
        Certificate_Unobtainable = 111,
        Unrecognized_Name = 112,
        Bad_Certificate_Status_Reponse = 113,
        Bad_Certificate_Hash_Value = 114,
        Unknown_PSK_Identity = 115,
        No_Application_Protocol = 120,
    }
}
