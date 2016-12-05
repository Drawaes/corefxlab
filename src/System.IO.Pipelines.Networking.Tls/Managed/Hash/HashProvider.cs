using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.IO.Pipelines.Networking.Tls.Internal.ManagedTls;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Hash
{
    public class HashProvider
    {
        private IntPtr _providerHandle;
        private int _bufferSizeNeededForState;
        private bool _isValid = false;
        private bool _isHmac;
        private NativeBufferPool _pool;
        private int _blockLength;

        public HashProvider(string provider, bool isHmac)
        {
            _isHmac = isHmac;
            var hashs = Interop.HashAlgorithms;
            for (int i = 0; i < hashs.Length; i++)
            {
                if (hashs[i].pszName == provider)
                {
                    _isValid = true;
                    break;
                }
            }
            if (!_isValid)
            {
                return;
            }
            IntPtr provPtr;
            Interop.CheckReturnOrThrow(
                Interop.BCryptOpenAlgorithmProvider(out provPtr, provider, null, _isHmac ? Interop.BCRYPT_ALG_HANDLE_HMAC_FLAG : 0));
            _providerHandle = provPtr;
            _bufferSizeNeededForState = Interop.GetObjectLength(_providerHandle);
            _blockLength = Interop.GetHashLength(_providerHandle);
        }

        public bool IsValid => _isValid;
        public int BufferSizeNeededForState => _bufferSizeNeededForState;
        public int BlockLength => _blockLength;

        public HashInstance GetLongRunningHash()
        {
            return new HashInstance(_providerHandle, _pool.Rent(_bufferSizeNeededForState));
        }

        public unsafe void HMac(byte* output, int outputLength, byte* secret, int secretLength, byte* message, int messageLength)
        {
            Interop.CheckReturnOrThrow(Interop.BCryptHash(_providerHandle,secret, secretLength, message, messageLength,output,outputLength ));
        }

        public void Dispose()
        {
            Interop.CheckReturnOrThrow(Interop.BCryptCloseAlgorithmProvider(_providerHandle, 0));
        }

        internal void SetBufferPool(NativeBufferPool pool)
        {
            _pool = pool;
        }
    }
}
