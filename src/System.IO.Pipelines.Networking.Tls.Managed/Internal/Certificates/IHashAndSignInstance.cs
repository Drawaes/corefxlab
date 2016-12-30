using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates
{
    internal interface IHashAndSignInstance:IHashInstance
    {
        ICertificate Certificate { get;}
    }
}
