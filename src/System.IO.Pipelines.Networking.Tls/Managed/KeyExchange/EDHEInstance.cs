using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.KeyExchange
{
    public class EDHEInstance : IKeyExchangeInstance
    {
        private readonly IntPtr _key;
        private readonly ManagedConnectionContext _context;
        private string _selectedCurve;
        private IntPtr _provider;

        public EDHEInstance(IntPtr key, ManagedConnectionContext context, IntPtr provider)
        {
            _context = context;
            _key = key;
            _provider = provider;
        }
        public void ProcessEcPointFormats(ReadableBuffer buffer)
        {
            throw new NotImplementedException();
        }

        public void ProcessSupportedGroupsExtension(ReadableBuffer buffer)
        {
            buffer = buffer.Slice(2);
            while (buffer.Length > 0)
            {
                var value = (EllipticCurves)buffer.ReadBigEndian<ushort>();
                var name = Internal.ManagedTls.InteropCurves.MapTlsCurve(value);
                if (name != null)
                {
                    _selectedCurve = name;
                    //We need to generate the key pair;
                    //Internal.ManagedTls.Interop.
                    throw new NotImplementedException();
                    return;
                }
            }
            throw new InvalidOperationException("No matching curve found");
        }

        public void WriteServerKeyExchange(ref WritableBuffer buffer)
        {
            throw new NotImplementedException();
        }
    }
}
