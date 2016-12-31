using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Internal
{
    public class CipherList
    {
        private Dictionary<ushort,CipherSuite> _ciphers = new Dictionary<ushort, CipherSuite>();

        public CipherList()
        {

        }
    }
}
