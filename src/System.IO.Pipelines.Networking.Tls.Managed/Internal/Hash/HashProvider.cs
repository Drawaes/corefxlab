using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Windows;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash
{
    public class HashProvider
    {
        private IntPtr _providerHandle;
        private int _bufferSizeNeededForState;
        private bool _isValid = true;
        private bool _isHmac;
        private NativeBufferPool _pool;
        private int _hashLength;
        private HashType _hashType;
        private IntPtr _algId;
        private int _algIdLength;

        public HashProvider(HashType hashType, bool isHmac)
        {
            _hashType = hashType;
            var provider = hashType.ToString();
            _isHmac = isHmac;
            _providerHandle = InteropProviders.OpenHashProvider(provider, isHmac);

            if (_providerHandle == IntPtr.Zero)
            {
                _isValid = false;
                return;
            }
            _bufferSizeNeededForState = InteropProperties.GetObjectLength(_providerHandle);
            _hashLength = InteropProperties.GetHashLength(_providerHandle);
            _algId = Marshal.StringToHGlobalUni(hashType + "\0");
            _algIdLength = (hashType.ToString().Length + 1) * 2;
        }

        public bool IsValid => _isValid;
        public int BufferSizeNeededForState => _bufferSizeNeededForState;
        public int HashLength => _hashLength;
        public HashType HashType => _hashType;
        public IntPtr AlgId => _algId;
        public int AlgIdLength => _algIdLength;

        public HashInstance GetLongRunningHash()
        {
            return new HashInstance(_providerHandle, _pool, _bufferSizeNeededForState, _hashLength);
        }

        //public unsafe void HashValue(byte* output, int outputLength, byte* secret, int secretLength, byte* message, int messageLength)
        //{
        //    Interop.CheckReturnOrThrow(Interop.BCryptHash(_providerHandle, secret, secretLength, message, messageLength, output, outputLength));
        //}

        public void Dispose()
        {
            if (_isValid)
            {
                InteropProviders.CloseProvider(_providerHandle);
                Marshal.FreeHGlobal(_algId);
                _isValid = false;
            }
        }

        internal void SetBufferPool(NativeBufferPool pool)
        {
            _pool = pool;
        }
    }
}

