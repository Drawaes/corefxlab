using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Unix
{
    internal unsafe static class InteropCrypto
    {
        public const string CryptoDll = "libeay32.dll";
        public const string SslDll = "ssleay32.dll";

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void locking_function(LockState mode, int threadNumber, byte* file, int line);
        [DllImport(CryptoDll, CallingConvention = CallingConvention.Cdecl)]
        private extern static void CRYPTO_set_locking_callback(locking_function lockingFunction);
        [DllImport(CryptoDll, CallingConvention = CallingConvention.Cdecl)]
        private extern static void OPENSSL_add_all_algorithms_noconf();
        [DllImport(CryptoDll, CallingConvention = CallingConvention.Cdecl)]
        private extern static void ERR_load_crypto_strings();
        [DllImport(CryptoDll, CallingConvention = CallingConvention.Cdecl)]
        private extern static void CRYPTO_free(void* pointer);
        [DllImport(CryptoDll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int CRYPTO_num_locks();
        [DllImport(SslDll, CallingConvention = CallingConvention.Cdecl)]
        private extern static void SSL_load_error_strings();
        [DllImport(SslDll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int SSL_library_init();
        [DllImport(CryptoDll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static int ERR_error_string_n(uint errorCode, byte* buffer, UIntPtr len );
        [DllImport(CryptoDll, CallingConvention = CallingConvention.Cdecl)]
        internal extern static uint ERR_get_error();
        
        [Flags]
        private enum LockState
        {
            CRYPTO_UNLOCK = 0x02,
            CRYPTO_READ = 0x04,
            CRYPTO_LOCK = 0x01,
            CRYPTO_WRITE = 0x08,
        }

        private unsafe static class LockStore
        {
            private static SemaphoreSlim[] _locks;
            internal static readonly locking_function Callback;

            static LockStore()
            {
                var numberOfLocks = CRYPTO_num_locks();
                _locks = new SemaphoreSlim[numberOfLocks];
                for (int i = 0; i < _locks.Length; i++)
                {
                    _locks[i] = new SemaphoreSlim(1);
                }
                Callback = HandleLock;
            }

            private static unsafe void HandleLock(LockState lockState, int lockId, byte* file, int lineNumber)
            {
                if ((lockState & LockState.CRYPTO_UNLOCK) > 0)
                {
                    _locks[lockId].Release();
                }
                else if ((lockState & LockState.CRYPTO_LOCK) > 0)
                {
                    _locks[lockId].Wait();
                }
            }
        }

        public static void Init()
        {
            CRYPTO_set_locking_callback(LockStore.Callback);
            ERR_load_crypto_strings();
            //SSL_load_error_strings();
            OPENSSL_add_all_algorithms_noconf();
            //ExceptionHelper.CheckOpenSslError(SSL_library_init());
        }
    }
}
