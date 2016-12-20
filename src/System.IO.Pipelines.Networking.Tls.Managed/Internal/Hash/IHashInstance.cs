﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash
{
    internal interface IHashInstance:IDisposable
    {
        int HashLength { get;}
        void HashData(ReadableBuffer buffer);
        unsafe void HashData(byte* buffer, int length);
        void HashData(Memory<byte> memory);
        unsafe void Finish(byte* output, int length, bool completed);
    }
}
