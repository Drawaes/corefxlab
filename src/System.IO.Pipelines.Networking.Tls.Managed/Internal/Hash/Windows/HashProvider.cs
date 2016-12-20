using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Windows;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash.Windows
{
    internal class HashProvider : IHashProvider
    {
        private IntPtr _hashHandle;
        private IntPtr _hmacHandle;
        private readonly HashType _hashType;
        private bool _isValid = false;
        private readonly int _bufferSizeNeededForState;
        private int _hashLength;
        private IntPtr _algId;
        private int _algIdLength;
        private NativeBufferPool _pool;

        public HashProvider(HashType hashType)
        {
            _hashType = hashType;
            var provider = hashType.ToString();
            _hashHandle = InteropProviders.OpenHashProvider(provider, false);
            _hmacHandle = InteropProviders.OpenHashProvider(provider, true);
            if (_hashHandle == IntPtr.Zero || _hmacHandle == IntPtr.Zero)
            {
                return;
            }
            _isValid = true;
            _bufferSizeNeededForState = InteropProperties.GetObjectLength(_hashHandle);
            _hashLength = InteropProperties.GetHashLength(_hashHandle);
            _algId = Marshal.StringToHGlobalUni(hashType + "\0");
            _algIdLength = (hashType.ToString().Length + 1) * 2;
        }

        public int HashLength => _hashLength;
        public IntPtr AlgId => _algId;
        public bool IsValid => _isValid;
        public int BufferSizeNeededForState => _bufferSizeNeededForState;
        public HashType HashType => _hashType;
        public int AlgIdLength => _algIdLength;

        public IHashInstance GetLongRunningHash(byte[] hmacKey)
        {
            if(hmacKey == null)
            {
                return new HashInstance(_hashHandle, null, _pool, _bufferSizeNeededForState, _hashLength);
            }
            else
            {
                return new HashInstance(_hmacHandle, hmacKey, _pool, _bufferSizeNeededForState, _hashLength);
            }
        }

        public unsafe void HmacValue(byte* output, int outputLength, byte* secret, int secretLength, byte* message, int messageLength)
        {
            ExceptionHelper.CheckReturnCode(InteropHash.BCryptHash(_hmacHandle, secret, secretLength, message, messageLength, output, outputLength));
        }

        internal void SetBufferPool(NativeBufferPool pool)
        {
            _pool = pool;
        }

        ~HashProvider()
        {
            Dispose();
        }

        public void Dispose()
        {
            if (_isValid)
            {
                InteropProviders.CloseProvider(_hashHandle);
                InteropProviders.CloseProvider(_hmacHandle);
                Marshal.FreeHGlobal(_algId);
                _isValid = false;
            }
            GC.SuppressFinalize(this);
        }
    }
}
