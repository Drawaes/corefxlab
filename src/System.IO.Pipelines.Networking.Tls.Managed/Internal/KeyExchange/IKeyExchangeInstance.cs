using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.KeyExchange
{
    internal interface IKeyExchangeInstance
    {
        void ProcessSupportedGroupsExtension(ReadableBuffer buffer);
        void ProcessEcPointFormats(ReadableBuffer buffer);
        void WriteServerKeyExchange(ref WritableBuffer buffer);
        byte[] ProcessClientKeyExchange(ReadableBuffer buffer);
        void SetSignature(IHashInstance hashInstance, ICertificate certificate);
    }
}
