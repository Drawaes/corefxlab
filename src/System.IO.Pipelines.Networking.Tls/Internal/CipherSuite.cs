using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Internal
{
    public class CipherSuite
    {
        private ushort _cipherCode;
        private string _cipherString;
        private TlsVersion[] _supportedVersions;

        public CipherSuite(ushort cipherCode, string cipherString, params TlsVersion[] supportedVersion)
        {
            _supportedVersions = supportedVersion;
            _cipherCode = cipherCode;
            _cipherString = cipherString;
            
        }

        public ushort CipherCode => _cipherCode;
        public string CipherString => _cipherString;

        public bool IsSupported(TlsVersion version)
        {
            for(int i = 0; i < _supportedVersions.Length;i++)
            {
                if(_supportedVersions[i] == version)
                {
                    return true;
                }
            }
            return false;
        }

        public IHashInstance GetHashInstance()
        {
            throw new NotImplementedException();
        }
    }
}
