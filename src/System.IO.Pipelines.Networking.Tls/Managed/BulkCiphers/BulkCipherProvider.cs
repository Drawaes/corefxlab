using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Internal.ManagedTls;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.BulkCiphers
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
        private static readonly byte[] s_BCRYPT_CHAIN_MODE_CBC = Encoding.Unicode.GetBytes("ChainingModeGCM\0");

        public BulkCipherProvider(string provider)
        {
            _providerName = provider;
            var splitProv = provider.Split('_');
            var parentProv = splitProv[0];
            var ciphers = Interop.CipherAlgorithms;
            for (int i = 0; i < ciphers.Length; i++)
            {
                if (ciphers[i].pszName == parentProv)
                {
                    _isValid = true;
                    break;
                }
            }
            if (!_isValid)
            {
                return;
            }
            _isValid = false;
            IntPtr provPtr;
            Interop.CheckReturnOrThrow(
                Interop.BCryptOpenAlgorithmProvider(out provPtr, parentProv, null, 0));
            try
            {
                _providerHandle = provPtr;
                _bufferSizeNeededForState = InteropProperties.GetObjectLength(_providerHandle);
                if (parentProv == "AES")
                {
                    var chainingMode = (BulkCipherChainingMode)Enum.Parse(typeof(BulkCipherChainingMode), splitProv[2]);
                    _nounceSaltLength = 4;
                    InteropProperties.SetBlockChainingMode(_providerHandle, chainingMode);
                    _keySizeInBytes = int.Parse(splitProv[1]) / 8;
                    var blockMode = InteropProperties.GetBlockChainingMode(_providerHandle);
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

        public BulkCipherKey GetCipherKey(byte[] key)
        {
            var returnKey = new BulkCipherKey(_providerHandle, _pool.Rent(_bufferSizeNeededForState), key);
            return returnKey;
        }

        public void SetBufferPool(NativeBufferPool pool)
        {
            _pool = pool;
        }

        public void Dispose()
        {
            if (_providerHandle != IntPtr.Zero)
            {
                Interop.BCryptCloseAlgorithmProvider(_providerHandle, 0);
                _providerHandle = IntPtr.Zero;
            }
        }
    }
}
