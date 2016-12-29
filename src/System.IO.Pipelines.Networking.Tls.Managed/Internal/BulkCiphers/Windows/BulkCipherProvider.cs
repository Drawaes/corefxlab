using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Windows;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Windows;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.BulkCiphers.Windows
{
    internal class BulkCipherProvider : IBulkCipherProvider
    {
        private bool _isValid;
        private SafeBCryptAlgorithmHandle _providerHandle;
        private readonly string _providerName;
        private readonly bool _requiresHmac = true;
        private int _bufferSizeNeededForState;
        private int _keySizeInBytes;
        private int _nonceSaltLength;
        private NativeBufferPool _pool;

        public BulkCipherProvider(string provider)
        {
            _providerName = provider;
            var splitProv = provider.Split('_');
            var parentProv = splitProv[0];
            _providerHandle = BCryptHelper.OpenBulkProvider(parentProv);
            if (_providerHandle == null)
            {
                _isValid = false;
                return;
            }
            try
            {
                _bufferSizeNeededForState = BCryptPropertiesHelper.GetObjectLength(_providerHandle);
                if (parentProv == "AES")
                {
                    var chainingMode = (BulkCipherChainingMode)Enum.Parse(typeof(BulkCipherChainingMode), splitProv[2], true);
                    if (chainingMode == BulkCipherChainingMode.CBC)
                    {
                        _requiresHmac = true;
                        _nonceSaltLength = 0;
                    }
                    else
                    {
                        _requiresHmac = false;
                        _nonceSaltLength = 4;
                    }
                    _keySizeInBytes = int.Parse(splitProv[1]) / 8;
                    BCryptPropertiesHelper.SetBlockChainingMode(_providerHandle, chainingMode);
                }
                else
                {
                    _keySizeInBytes = BCryptPropertiesHelper.GetKeySizeInBits(_providerHandle) / 8;
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
        public int NonceSaltLength => _nonceSaltLength;
        public int KeySizeInBytes => _keySizeInBytes;
        public int BufferSizeNeededForState => _bufferSizeNeededForState;
        public bool RequiresHmac => _requiresHmac;

        public unsafe IBulkCipherInstance GetCipherKey(byte* key, int keyLength, CipherSuite suite)
        {
            if (_requiresHmac)
            {
                return new HmacCipherKey(_providerHandle, suite, _pool, _bufferSizeNeededForState, key, keyLength);
            }
            else
            {
                return new AeadCipherKey(_providerHandle, _pool, _bufferSizeNeededForState, key, keyLength);
            }
        }

        public void SetBufferPool(NativeBufferPool pool)
        {
            _pool = pool;
        }

        public void Dispose()
        {
            _providerHandle.Dispose();
        }
    }
}
