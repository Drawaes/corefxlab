﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.KeyExchange
{
    public interface IKeyExchangeInstance
    {
        void ProcessSupportedGroupsExtension(ReadableBuffer buffer);
        void ProcessEcPointFormats(ReadableBuffer buffer);
        void WriteServerKeyExchange(ref WritableBuffer buffer);
    }
}
