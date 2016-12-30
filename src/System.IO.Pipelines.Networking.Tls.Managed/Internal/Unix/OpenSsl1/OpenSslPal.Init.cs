using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using static global::Interop.Libeay32;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Unix
{
    internal partial class OpenSslPal
    {
        private partial class OpenSsl1Pal : IOpenSslHelper
        {
            internal OpenSsl1Pal()
            {
                CRYPTO_set_locking_callback(LockStore.Callback);
                ERR_load_crypto_strings();
                OPENSSL_add_all_algorithms_noconf();
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
        }
    }
}
