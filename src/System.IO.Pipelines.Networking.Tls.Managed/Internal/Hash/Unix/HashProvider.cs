using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Unix;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash.Unix
{
    internal class HashProvider:IHashProvider
    {
        private IntPtr _digestPtr;
        private HashType _hashType;
        private int _hashLength;

        public HashProvider(IntPtr digestPtr, HashType hashType)
        {
            _hashType = hashType;
            _digestPtr = digestPtr;
            _hashLength = InteropHash.EVP_MD_size(digestPtr);
        }

        public IntPtr AlgId => _digestPtr;

        public int AlgIdLength => -1;
        
        public int HashLength=> _hashLength;

        public HashType HashType => _hashType;

        public bool IsValid => true;

        public void Dispose()
        {
        }

        public unsafe IHashInstance GetLongRunningHash(byte[] hmacKey)
        {
            if(hmacKey == null)
            {
                return new HashInstance(_hashLength, _digestPtr);
            }
            else
            {
                fixed (void* keyPtr = hmacKey)
                {
                    return new HmacInstance(_hashLength, _digestPtr, (IntPtr)keyPtr, hmacKey.Length );
                }
            }
        }

        public unsafe void HmacValue(byte* output, int outputLength, byte* secret, int secretLength, byte* message, int messageLength)
        {
            var hmac = new HmacInstance(_hashLength, _digestPtr, (IntPtr)secret, secretLength);
            hmac.HashData( message, messageLength);
            hmac.Finish(output, outputLength,true);
        }
    }
}
