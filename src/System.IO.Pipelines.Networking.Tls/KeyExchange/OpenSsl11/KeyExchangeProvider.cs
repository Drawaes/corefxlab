using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using static Interop.LibCrypto;

namespace System.IO.Pipelines.Networking.Tls.KeyExchange.OpenSsl11
{
    public class KeyExchangeProvider : IKeyExchangeProvider
    {
        private string[] _curveNames;
        private int[] _nidValues;

        public unsafe KeyExchangeProvider()
        {
            IntPtr size = ThrowOnError(EC_get_builtin_curves(null, IntPtr.Zero));
            var array = stackalloc EC_builtin_curve[size.ToInt32()];
            size = ThrowOnError(EC_get_builtin_curves(array, size));
            var totalCurves = size.ToInt32();
            _curveNames = new string[totalCurves];
            _nidValues = new int[totalCurves];
            for (int i = 0; i < totalCurves; i++)
            {
                var name = OBJ_nid2ln(array[i].nid);
                _curveNames[i] = name;
                _nidValues[i] = array[i].nid;
            }
        }

        public IKeyExchangeInstance GetInstance(NamedGroup group)
        {
            if (((ushort)group & 0xFF00) == 0)
            {
                var groupName = group.ToString();
                for (int i = 0; i < _curveNames.Length; i++)
                {
                    if (_curveNames[i] == groupName)
                    {
                        return new EcdheKeyExchangeInstance(_nidValues[i], group);
                    }
                }
            }
            return null;
        }

        public IKeyExchangeInstance GetInstance(NamedGroup group, ReadableBuffer keyData)
        {
            var returnValue = GetInstance(group);
            if (returnValue == null)
            {
                return null;
            }
            returnValue.SetClientKey(keyData);
            return returnValue;
        }
    }
}
