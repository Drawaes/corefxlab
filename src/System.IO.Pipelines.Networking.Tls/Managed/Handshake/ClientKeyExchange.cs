using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Handshake
{
    public static class ClientKeyExchange
    {
        public unsafe static void ProcessClientKeyExchange(ReadableBuffer readBuffer, ManagedConnectionContext context)
        {
            context.HandshakeHash.HashData(readBuffer);
            readBuffer = readBuffer.Slice(1); // Slice off type
            uint contentSize = readBuffer.ReadBigEndian<ushort>();
            readBuffer = readBuffer.Slice(2);
            contentSize = (contentSize << 8) + readBuffer.ReadBigEndian<byte>();
            readBuffer = readBuffer.Slice(1);

            if (readBuffer.Length != contentSize)
            {
                throw new IndexOutOfRangeException($"The message buffer contains the wrong amount of data for our operation");
            }

            if (context.CipherSuite.ExchangeCipher == KeyExchangeCipher.RSA)
            {
                var length = readBuffer.ReadBigEndian<ushort>();
                readBuffer = readBuffer.Slice(2);
                if (readBuffer.Length != length)
                {
                    throw new ArgumentOutOfRangeException("Buffer size does not match the content header");
                }
                Memory<byte> encryptedData;
                if (readBuffer.IsSingleSpan)
                {
                    encryptedData = readBuffer.First;
                }
                else
                {
                    throw new NotImplementedException("Exercise for the reader");
                }
                var decrypted = Internal.ManagedTls.InteropCertificates.DecryptInPlace(context.SecurityContext.PrivateKeyHandle, encryptedData);
                var version = decrypted.Span.Read<ushort>();
                if (version != 0x0303)
                {
                    throw new InvalidOperationException("Bad version after decrypting the client random");
                }

                //This is the amount of key data we need to generate
                var keyLength = context.CipherInfo.BulkCipher.NounceSaltLength + context.CipherInfo.BulkCipher.KeySizeInBytes + context.CipherInfo.Hmac.BlockLength;
                keyLength *= 2;


                byte[] preMasterSecret = new byte[48];

                //MasterSecretCalculation.CalculateMasterSecret(ref state, preMasterSecret);

                return;

            }
            throw new InvalidOperationException();
        }
    }
}
