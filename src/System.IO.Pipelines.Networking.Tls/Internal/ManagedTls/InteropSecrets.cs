using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Internal.ManagedTls
{
    public unsafe static class InteropSecrets
    {
        private const string Dll = "Bcrypt.dll";

        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern ReturnCodes BCryptSecretAgreement(IntPtr hPrivKey, IntPtr hPubKey, out IntPtr phSecret, uint dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern ReturnCodes BCryptDeriveKey(IntPtr hSharedSecret, string pwszKDF, void* pParameterList, IntPtr pbDerivedKey, int cbDerivedKey, out int pcbResult, uint dwFlags);

        private const string BCRYPT_KDF_TLS_PRF = "TLS_PRF";

        [StructLayout(LayoutKind.Sequential)]
        private struct BCryptBufferDesc
        {
            public uint ulVersion;
            public int cBuffers;
            public void* pBuffers;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BCryptBuffer
        {
            public int cbBuffer;             // Length of buffer, in bytes
            public BufferTypes BufferType;           // Buffer type
            public void* pvBuffer;             // Pointer to buffer
        }

        private enum BufferTypes : uint
        {
            KDF_HASH_ALGORITHM = 0x0,
            KDF_SECRET_PREPEND = 0x1,
            KDF_SECRET_APPEND = 0x2,
            KDF_HMAC_KEY = 0x3,
            KDF_TLS_PRF_LABEL = 0x4,
            KDF_TLS_PRF_SEED = 0x5,
            KDF_SECRET_HANDLE = 0x6,
            KDF_TLS_PRF_PROTOCOL = 0x7,
            KDF_ALGORITHMID = 0x8,
            KDF_PARTYUINFO = 0x9,
            KDF_PARTYVINFO = 0xA,
            KDF_SUPPPUBINFO = 0xB,
            KDF_SUPPPRIVINFO = 0xC,
            KDF_LABEL = 0xD,
            KDF_CONTEXT = 0xE,
            KDF_SALT = 0xF,
            KDF_ITERATION_COUNT = 0x10,
        }

        public static void CalculateMasterSecret(IntPtr sharedSecret, byte[] seed)
        {
            seed = seed.Skip(13).ToArray();
            fixed (void* seedPtr = seed)
            {
                var buffDescription = new BCryptBufferDesc();
                var bufferHash = new BCryptBuffer();
                bufferHash.BufferType = BufferTypes.KDF_HASH_ALGORITHM;
                var ptr = Marshal.StringToHGlobalUni("SHA256\0");
                var ptrLabel = Marshal.StringToHGlobalAnsi("master secret");

                bufferHash.pvBuffer = ptr.ToPointer();
                bufferHash.cbBuffer = "SHA256\0".Length * 2;
                uint version = 0x0303;

                var bufferArray = stackalloc BCryptBuffer[4];
                bufferArray[0] = bufferHash;
                bufferArray[1] = new BCryptBuffer() { BufferType = BufferTypes.KDF_TLS_PRF_LABEL, cbBuffer = "master secret".Length, pvBuffer = (void*)ptrLabel };
                bufferArray[2] = new BCryptBuffer() { BufferType = BufferTypes.KDF_TLS_PRF_SEED, cbBuffer = seed.Length, pvBuffer = seedPtr };
                bufferArray[3] = new BCryptBuffer() { BufferType = BufferTypes.KDF_TLS_PRF_PROTOCOL, cbBuffer = 4, pvBuffer = &version };

                buffDescription.cBuffers = 4;
                buffDescription.pBuffers = bufferArray;

                int sizeOfResult;
                Interop.CheckReturnOrThrow(
                    BCryptDeriveKey(sharedSecret, BCRYPT_KDF_TLS_PRF, &buffDescription, IntPtr.Zero, 0, out sizeOfResult, 0));

                var masterSecret = new byte[sizeOfResult];
                fixed(void* msPtr = masterSecret)
                {
                    Interop.CheckReturnOrThrow(
                    BCryptDeriveKey(sharedSecret, BCRYPT_KDF_TLS_PRF, &buffDescription, (IntPtr)msPtr, sizeOfResult, out sizeOfResult, 0));

                }
                System.IO.File.WriteAllText("C:\\Code\\KeyLog\\Master.log",BitConverter.ToString(masterSecret));
            }
        }
    }
}
