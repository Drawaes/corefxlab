using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Hash;
using System.IO.Pipelines.Networking.Tls.Managed.KeyExchange;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Handshake
{
    public static class ClientKeyExchange
    {
        public unsafe static void ProcessClientKeyExchange(ReadableBuffer readBuffer, ManagedConnectionContext context)
        {
            context.ClientFinishedHash.HashData(readBuffer);
            context.ServerFinishedHash.HashData(readBuffer);

            readBuffer = readBuffer.Slice(1); // Slice off type
            uint contentSize = readBuffer.ReadBigEndian<ushort>();
            readBuffer = readBuffer.Slice(2);
            contentSize = (contentSize << 8) + readBuffer.ReadBigEndian<byte>();
            readBuffer = readBuffer.Slice(1);

            if (readBuffer.Length != contentSize)
            {
                throw new IndexOutOfRangeException($"The message buffer contains the wrong amount of data for our operation");
            }

            //if (context.CipherSuite.ExchangeCipher == KeyExchangeType.RSA)
            //{
            //    var length = readBuffer.ReadBigEndian<ushort>();
            //    readBuffer = readBuffer.Slice(2);
            //    if (readBuffer.Length != length)
            //    {
            //        throw new ArgumentOutOfRangeException("Buffer size does not match the content header");
            //    }
            //    Memory<byte> encryptedData;
            //    if (readBuffer.IsSingleSpan)
            //    {
            //        encryptedData = readBuffer.First;
            //    }
            //    else
            //    {
            //        throw new NotImplementedException("Exercise for the reader");
            //    }
            //    var decrypted = Internal.ManagedTls.InteropCertificates.DecryptInPlace(context.SecurityContext.PrivateKeyHandle, encryptedData);
            //    var version = decrypted.Span.Read<ushort>();
            //    if (version != 0x0303)
            //    {
            //        throw new InvalidOperationException("Bad version after decrypting the premaster secret");
            //    }
            //    var cipherSuite = context.CipherSuite;
            //    //This is the amount of key data we need to generate
            //    var keyLength = cipherSuite.KeyMaterialRequired;
                
            //    byte[] preMasterSecret = decrypted.ToArray();
            //    byte[] masterSecret = new byte[48];

            //    P_hash(cipherSuite.Hmac, masterSecret, preMasterSecret, context.SeedBuffer.ToArray());
            //    byte[] keyMaterial = new byte[keyLength];
            //    context.SetSeedKeyExpansion();
            //    context.SetMasterSecret(masterSecret);
            //    P_hash(cipherSuite.Hmac, keyMaterial, masterSecret, context.SeedBuffer.ToArray());

            //    var clientWrite = keyMaterial.Take(cipherSuite.BulkCipher.KeySizeInBytes).ToArray();
            //    var serverWrite = keyMaterial.Skip(cipherSuite.BulkCipher.KeySizeInBytes).Take(cipherSuite.BulkCipher.KeySizeInBytes).ToArray();

            //    var clientNounce = keyMaterial.Skip((cipherSuite.BulkCipher.KeySizeInBytes) * 2).Take(cipherSuite.BulkCipher.NounceSaltLength).ToArray();
            //    var serverNounce = keyMaterial.Skip(cipherSuite.BulkCipher.KeySizeInBytes * 2 + cipherSuite.BulkCipher.NounceSaltLength).ToArray();
                
            //    var clientWriteKey = cipherSuite.BulkCipher.GetCipherKey(clientWrite);
            //    var serverWriteKey = cipherSuite.BulkCipher.GetCipherKey(serverWrite);
            //    context.SetClientKeyAndNounce(clientWriteKey, clientNounce);
            //    context.SetServerKeyAndNounce(serverWriteKey, serverNounce);
            //    return;
            //}
           throw new InvalidOperationException();
        }

        internal unsafe static void P_hash(HashProvider hash, byte[] keyMaterial, byte[] secret, byte[] seed)
        {
            fixed (byte* secretPtr = secret)
            {
                var a1 = stackalloc byte[hash.BlockLength + seed.Length];
                Span<byte> a1Span = new Span<byte>(a1, hash.BlockLength + seed.Length);
                Span<byte> seedSpan = new Span<byte>(seed);
                seedSpan.CopyTo(a1Span.Slice(hash.BlockLength));
                var seedPtr = a1 + hash.BlockLength;
                hash.HashValue(a1, hash.BlockLength, secretPtr, secret.Length, seedPtr, seed.Length);
                var currentKeyData = stackalloc byte[hash.BlockLength];

                int keyMaterialIndex = 0;
                while (true)
                {
                    hash.HashValue(currentKeyData, hash.BlockLength, secretPtr, secret.Length, a1, hash.BlockLength + seed.Length);
                    for (int i = 0; i < hash.BlockLength; i++)
                    {
                        keyMaterial[keyMaterialIndex] = currentKeyData[i];
                        keyMaterialIndex++;
                        if (keyMaterialIndex == keyMaterial.Length)
                        {
                            return;
                        }
                    }
                    hash.HashValue(a1, hash.BlockLength, secretPtr, secret.Length, a1, hash.BlockLength);
                }
            }
        }
    }
}
