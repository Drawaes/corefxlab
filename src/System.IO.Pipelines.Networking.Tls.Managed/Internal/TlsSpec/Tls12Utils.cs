using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.TlsSpec
{
    internal unsafe static class Tls12Utils
    {
        public const ushort TLS_VERSION = 0x0303;
        public const int RANDOM_LENGTH = 32;
        public const int AEAD_TAG_LENGTH = 16;
        public const int VERIFY_DATA_LENGTH = 12;
        internal const int MASTER_SECRET_LENGTH = 48;
        private const string MASTER_SECRET = "master secret";
        private const string KEY_EXPANSION = "key expansion";
        private const string CLIENT_FINISHED = "client finished";
        private const string SERVER_FINISHED = "server finished";

        internal static readonly IntPtr MasterSecretPointer = Marshal.StringToHGlobalAnsi(MASTER_SECRET);
        internal static readonly IntPtr KeyExpansionPointer = Marshal.StringToHGlobalAnsi(KEY_EXPANSION);
        internal static readonly IntPtr ClientFinishedPointer = Marshal.StringToHGlobalAnsi(CLIENT_FINISHED);
        internal static readonly IntPtr ServerFinishedPointer = Marshal.StringToHGlobalAnsi(SERVER_FINISHED);
        internal static readonly int MasterSecretSize = MASTER_SECRET.Length;
        internal static readonly int KeyExpansionSize = KEY_EXPANSION.Length;
        internal static readonly int ClientFinishedSize = CLIENT_FINISHED.Length;
        internal static readonly int ServerFinishedSize = SERVER_FINISHED.Length;
        internal static Span<byte> GetClientFinishedSpan() => new Span<byte>((void*)ClientFinishedPointer, ClientFinishedSize);
        internal static Span<byte> GetServerFinishedSpan() => new Span<byte>((void*)ServerFinishedPointer, ServerFinishedSize);
        internal static Span<byte> GetMasterSecretSpan() => new Span<byte>((void*) MasterSecretPointer, MasterSecretSize);

        public static unsafe void P_Hash12(IHashProvider hash, byte[] keyMaterial, byte[] secret, byte[] seed)
        {
            fixed (byte* secretPtr = secret)
            {
                var a1 = stackalloc byte[hash.HashLength + seed.Length];
                Span<byte> a1Span = new Span<byte>(a1, hash.HashLength + seed.Length);
                Span<byte> seedSpan = new Span<byte>(seed);
                seedSpan.CopyTo(a1Span.Slice(hash.HashLength));
                var seedPtr = a1 + hash.HashLength;
                hash.HmacValue(a1, hash.HashLength, secretPtr, secret.Length, seedPtr, seed.Length);
                var currentKeyData = stackalloc byte[hash.HashLength];

                int keyMaterialIndex = 0;
                while (true)
                {
                    hash.HmacValue(currentKeyData, hash.HashLength, secretPtr, secret.Length, a1, hash.HashLength + seed.Length);
                    for (int i = 0; i < hash.HashLength; i++)
                    {
                        keyMaterial[keyMaterialIndex] = currentKeyData[i];
                        keyMaterialIndex++;
                        if (keyMaterialIndex == keyMaterial.Length)
                        {
                            return;
                        }
                    }
                    hash.HmacValue(a1, hash.HashLength, secretPtr, secret.Length, a1, hash.HashLength);
                }
            }
        }
    }
}
