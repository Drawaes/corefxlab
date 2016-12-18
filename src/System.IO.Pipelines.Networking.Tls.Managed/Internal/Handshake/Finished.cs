using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Handshake
{
    internal static class Finished
    {
        private const int VERIFY_DATA_LENGTH = 12;

        public unsafe static void ProcessClient(ReadableBuffer buffer, ConnectionState state, byte[] masterSecret)
        {
            //THIS METHOD is very allocaty for no good reason need to revist the P_Hash function
            //and this method that uses it
            var verifyData = new byte[VERIFY_DATA_LENGTH];
            var hashResult = new byte[state.HandshakeHash.HashSize + TlsImplementation.ClientFinishedSize];
            fixed (byte* hashPointer = hashResult)
            {
                state.HandshakeHash.Finish(hashPointer + TlsImplementation.ClientFinishedSize, state.HandshakeHash.HashSize, false);
            }
            //We have our handshake hash now we p_hash it to get down to the size we want but first we copy in the client finished message
            TlsImplementation.GetClientFinishedSpan().CopyTo(new Span<byte>(hashResult));
            TlsImplementation.P_Hash12(state.CipherSuite.Hmac,verifyData, masterSecret, hashResult);
            //Make sure we include this message in the server finished
            state.HandshakeHash.HashData(buffer);
            //So we have what we think the client finished hmac should be... what is it really?
            //lets check it, if we find an error we keep checking so we reduce timing side channels
            int currentIndex = 0;
            bool match = true;
            buffer = buffer.Slice(4,12);
            while (buffer.Length > 0)
            {
                if (currentIndex >= verifyData.Length)
                {
                    match = false;
                }
                else
                {
                    if (buffer.ReadLittleEndian<byte>() != verifyData[currentIndex])
                    {
                        match = false;
                    }
                }
                currentIndex++;
                buffer = buffer.Slice(1);
            }
            if (!match)
            {
                throw new InvalidOperationException("Client Verify didn't match");
            }
        }

        public static unsafe void WriteServer(ref WritableBuffer buffer, ConnectionState state, byte[] masterSecret)
        {
            var frame = new FrameWriter(ref buffer, TlsFrameType.Handshake, state);
            var handshakeFrame = new HandshakeWriter(ref buffer, state, HandshakeMessageType.Finished);

            var hashResult = new byte[state.HandshakeHash.HashSize + TlsImplementation.ServerFinishedSize];
            fixed (byte* hashPtr = hashResult)
            {
                state.HandshakeHash.Finish(hashPtr + TlsImplementation.ServerFinishedSize, state.HandshakeHash.HashSize, true);
            }
            TlsImplementation.GetServerFinishedSpan().CopyTo(hashResult);

            var verifyData = new byte[VERIFY_DATA_LENGTH];
            TlsImplementation.P_Hash12(state.CipherSuite.Hmac, verifyData, masterSecret, hashResult);
            buffer.Write(new Span<byte>(verifyData));

            handshakeFrame.Finish(ref buffer);
            frame.Finish(ref buffer);
        }
    }
}
