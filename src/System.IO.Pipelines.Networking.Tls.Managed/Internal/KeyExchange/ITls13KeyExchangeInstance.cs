using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.KeyExchange
{
    internal interface ITls13KeyExchangeInstance
    {
        bool HasClientKey { get;}
        NamedGroup Group { get;}
        int KeySize { get;}

        void SetClientKey(ReadableBuffer readableBuffer);
        void GetPublicKey(ref WritableBuffer outBuffer);
        void GenerateTrafficKeys(IConnectionState state);
    }
}
