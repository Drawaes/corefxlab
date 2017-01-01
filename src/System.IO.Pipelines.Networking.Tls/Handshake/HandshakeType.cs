﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Handshake
{
    public enum HandshakeType : byte
    {
        client_hello = 1,
        server_hello = 2,
        new_session_ticket = 4,
        end_of_early_data = 5,
        hello_retry_request = 6,
        encrypted_extensions = 8,
        certificate = 11,
        certificate_request = 13,
        certificate_verify = 15,
        finished = 20,
        key_update = 24,
    }
}
