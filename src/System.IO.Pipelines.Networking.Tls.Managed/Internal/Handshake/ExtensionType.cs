using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Handshake
{
    public enum ExtensionType : ushort
    {
        Server_name = 0,//[RFC6066]
        Max_fragment_length = 1,//[RFC6066]
        Client_certificate_url = 2,//[RFC6066]
        Trusted_ca_keys = 3,//[RFC6066]
        Truncated_hmac = 4,//[RFC6066]
        Status_request = 5,//[RFC6066]
        User_mapping = 6,//[RFC4681]
        Client_authz = 7,//[RFC5878]
        Server_authz = 8,//[RFC5878]
        Cert_type = 9,//[RFC6091]
        Supported_groups = 10,//(renamed from "elliptic_curves")	[RFC4492]        [RFC7919]
        Ec_point_formats = 11,//[RFC4492]
        Srp = 12,//[RFC5054]
        Signature_algorithms = 13,//[RFC5246]
        Use_srtp = 14,//[RFC5764]
        Heartbeat = 15,//[RFC6520]
        Application_layer_protocol_negotiation = 16,//[RFC7301]
        Status_request_v2 = 17,//[RFC6961]
        Signed_certificate_timestamp = 18,//[RFC6962]
        Client_certificate_type = 19,//[RFC7250]
        Server_certificate_type = 20,//[RFC7250]
        Padding = 21,//[RFC7685]
        Encrypt_then_mac = 22,//[RFC7366]
        Extended_master_secret = 23,//[RFC7627]
        Token_binding = 24,//(TEMPORARY - registered 2016-02-04, expires 2017-02-04)	[draft-ietf-tokbind-negotiation]
        Cached_info = 25,//[RFC7924]
        SessionTicket = 35,//[RFC4507]
        Renegotiation_info = 65281, //[RFC5746]

        //TLS 1.3
        Key_Share = 40,
        Pre_Shared_Key = 41,
        Early_Data = 42,
        Supported_Versions = 43,
        Cookie = 44,
        Psk_Key_Exchange_Modes = 45,
        Certificate_Authorities = 47,
        Oid_Filters = 48,
    }
}
