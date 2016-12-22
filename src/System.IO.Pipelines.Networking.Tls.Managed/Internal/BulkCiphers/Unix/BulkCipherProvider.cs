using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Unix;
using System.Linq;
using System.Threading.Tasks;
using static System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Unix.InteropBulkCiphers;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.BulkCiphers.Unix
{
    internal class BulkCipherProvider:IBulkCipherProvider
    {
        private IntPtr _providerHandle;
        private bool _isAead;
        private int _keySizeInBytes;
        private int _nonceSaltLength;

        public BulkCipherProvider(IntPtr providerHandle, bool isAead)
        {
            _providerHandle = providerHandle;
            _isAead = isAead;
            _keySizeInBytes = ExceptionHelper.CheckCtrlForError(EVP_CIPHER_key_length(_providerHandle));
            if(_isAead)
            {
                _nonceSaltLength = 4;
            }
        }

        public bool IsValid => true;

        public int NonceSaltLength => _nonceSaltLength;

        public int KeySizeInBytes => _keySizeInBytes;
        
        public bool RequiresHmac => !_isAead;
        
        public unsafe IBulkCipherInstance GetCipherKey(byte* key, int keyLength)
        {
            if(_isAead)
            {
                return new AeadCipherKey(key,keyLength, _providerHandle);
            }
            throw new NotImplementedException();
        }

        public void Dispose()
        {
        }
    }
}
