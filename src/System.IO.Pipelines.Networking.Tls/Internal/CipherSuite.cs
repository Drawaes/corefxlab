using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Hashes;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Internal
{
    public class CipherSuite
    {
        private ushort _cipherCode;
        private string _cipherString;
        private TlsVersion[] _supportedVersions;
        private HashType _hashType;
        private IHashProvider _hashProvider;

        public CipherSuite(ushort cipherCode, string cipherString, IHashProvider hashProvider, params TlsVersion[] supportedVersion)
        {
            _hashProvider = hashProvider;
            _supportedVersions = supportedVersion;
            _cipherCode = cipherCode;
            _cipherString = cipherString;
            var withSplit = cipherString.Split(new string[] { "WITH" },StringSplitOptions.RemoveEmptyEntries);
            string bulkAndCipher;
            if(withSplit.Length == 2)
            {
                bulkAndCipher = withSplit[1];
            }
            else
            {
                bulkAndCipher = withSplit[0];
            }
            var hashIndex = bulkAndCipher.LastIndexOf('_');
            var hash = bulkAndCipher.Substring(hashIndex + 1);
            if(!Enum.TryParse(hash, out _hashType))
            {
                throw new InvalidOperationException();
            }
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
            return _hashProvider.GetHashInstance(_hashType);
        }
    }
}
