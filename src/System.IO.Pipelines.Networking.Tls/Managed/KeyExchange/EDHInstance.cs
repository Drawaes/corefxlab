using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.KeyExchange
{
    public class EDHInstance:IKeyExchangeInstance
    {
        private IntPtr _keyHandle;
        private ManagedConnectionContext _context;
        private string _selectedCurve;

        public EDHInstance(IntPtr keyHandle, ManagedConnectionContext context)
        {
            _keyHandle = keyHandle;
            _context = context;
        }

        public void ProcessSupportedGroupsExtension(ReadableBuffer buffer)
        {
            buffer = buffer.Slice(2);
            while(buffer.Length > 0)
            {
                var value = (EllipticCurves) buffer.ReadBigEndian<ushort>();
                var name = Internal.ManagedTls.InteropCurves.MapTlsCurve(value);
                if(name != null)
                {
                    _selectedCurve = name;
                    return;
                }
            }
            throw new InvalidOperationException("No matching curve found");
        }

        public void ProcessEcPointFormats(ReadableBuffer buffer)
        {
            throw new NotImplementedException();
        }

        public void WriteServerKeyExchange(ref WritableBuffer buffer)
        {
            throw new NotImplementedException();
        }

        public void ProcessClientKeyExchange(ReadableBuffer buffer)
        {
            throw new NotImplementedException();
        }
    }
}
