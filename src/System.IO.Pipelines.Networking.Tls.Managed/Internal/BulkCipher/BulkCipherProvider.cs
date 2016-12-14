using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Windows;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.BulkCipher
{
    public class BulkCipherProvider:IDisposable
    {
        private readonly bool _isValid;
        private IntPtr _providerHandle;
        private int _bufferSizeNeededForState;
        private NativeBufferPool _pool;
        private int _nounceSaltLength;
        private int _keySizeInBytes;
        private readonly string _providerName;
        private readonly bool _requiresHmac = true;

        public BulkCipherProvider(string provider)
        {
            _providerName = provider;
            var splitProv = provider.Split('_');
            var parentProv = splitProv[0];
            _providerHandle = InteropProviders.OpenBulkProvider(parentProv);
            if(_providerHandle == IntPtr.Zero)
            {
                _isValid = false;
                return;
            }
            try
            {
                _bufferSizeNeededForState = InteropProperties.GetObjectLength(_providerHandle);
                if (parentProv == "AES")
                {
                    var chainingMode = (BulkCipherChainingMode)Enum.Parse(typeof(BulkCipherChainingMode), splitProv[2],true);
                    if(chainingMode == BulkCipherChainingMode.CBC)
                    {
                        _requiresHmac = true;
                    }
                    _keySizeInBytes = int.Parse(splitProv[1]) / 8;
                    InteropProperties.SetBlockChainingMode(_providerHandle, chainingMode);
                    _nounceSaltLength = 4;
                }
                else
                {
                    _keySizeInBytes = InteropProperties.GetKeySizeInBits(_providerHandle) / 8;
                }
                _isValid = true;
            }
            catch
            {
                Dispose();
                throw;
            }
        }

        public bool IsValid => _isValid;
        public int NounceSaltLength => _nounceSaltLength;
        public int KeySizeInBytes => _keySizeInBytes;
        public int BufferSizeNeededForState => _bufferSizeNeededForState;
        public bool RequiresHmac => _requiresHmac;

        public void SetBufferPool(NativeBufferPool pool)
        {
            _pool = pool;
        }

        public void Dispose()
        {
            if (_providerHandle != IntPtr.Zero)
            {
                InteropProviders.CloseProvider(_providerHandle);
                _providerHandle = IntPtr.Zero;
            }
        }
    }
}
