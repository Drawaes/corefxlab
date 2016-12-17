﻿using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Windows;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.KeyExchange
{
    internal class NoneExchangeProviderInstance : IKeyExchangeInstance
    {
        private ICertificate _certificate;
        private ConnectionState _state;

        public NoneExchangeProviderInstance(ICertificate certificate, ConnectionState state)
        {
            _state = state;
            _certificate = certificate;
        }

        public void Dispose()
        {
            throw new NotImplementedException();
        }

        public unsafe byte[] ProcessClientKeyExchange(ReadableBuffer buffer)
        {
            //Pull off the header and length
            buffer = buffer.Slice(6);
            
            //According to https://tools.ietf.org/html/rfc5246
            //We should generate a random master secret. If anything goes wrong
            //we carry on as if it is all okay and fail later on, this defeats
            //padding oracle attacks, it means we have to make the random even if
            //we doing use it just to keep in a semi constant time
            var handleForAllocation = default(GCHandle);
            byte[] masterSecret = new byte[TlsImplementation.MASTER_SECRET_LENGTH];
            InteropRandom.GetRandom(masterSecret);
            _state.HandshakeHash.HashData(buffer);
            try
            {

                void* memPointer;
                if (buffer.IsSingleSpan)
                {
                    if (!buffer.First.TryGetPointer(out memPointer))
                    {
                        throw new NotImplementedException();
                    }
                }
                else
                {
                    byte[] dataToDecrypt = buffer.ToArray();
                    handleForAllocation = GCHandle.Alloc(dataToDecrypt, GCHandleType.Pinned);
                    memPointer = (void*)handleForAllocation.AddrOfPinnedObject();
                }
                var length = _certificate.Decrypt((IntPtr)memPointer, buffer.Length, (IntPtr)memPointer, buffer.Length);
                if (length < masterSecret.Length)
                {
                    //Forget it its garbage we will carry on with the random master secret
                    return masterSecret;
                }
                // Check for downgrade
                if(buffer.ReadBigEndian<ushort>() != (ushort)_state.TlsVersion)
                {
                    //Version is wrong so return random
                    return masterSecret;
                }
                var preMasterSecret = buffer.Slice(0,length).ToArray();
                var seed = new byte[_state.ClientRandom.Length + _state.ServerRandom.Length + TlsImplementation.MasterSecretSize];
                var seedSpan = new Span<byte>(seed);
                var seedLabel = new Span<byte>((byte*)TlsImplementation.MasterSecretPointer, TlsImplementation.MasterSecretSize);
                seedLabel.CopyTo(seedSpan);
                seedSpan = seedSpan.Slice(seedLabel.Length);

                var clientRandom = new Span<byte>(_state.ClientRandom);
                clientRandom.CopyTo(seedSpan);
                seedSpan = seedSpan.Slice(clientRandom.Length);
                var serverRandom = new Span<byte>(_state.ServerRandom);
                serverRandom.CopyTo(seedSpan);

                TlsImplementation.P_Hash12(_state.CipherSuite.Hmac, masterSecret,preMasterSecret,seed );
            }
            catch
            {
                //Anything went wrong? Tough we need to eat the exception and carry on
                //Nothing to see here, due to timing side channel attacks at this point
                //on padding schemes etc
            }
            finally
            {
                if (handleForAllocation.IsAllocated)
                {
                    handleForAllocation.Free();
                }
            }
            return masterSecret;
        }

        public void ProcessEcPointFormats(ReadableBuffer buffer)
        {
        }

        public void ProcessSupportedGroupsExtension(ReadableBuffer buffer)
        {
        }

        public void WriteServerKeyExchange(ref WritableBuffer buffer)
        {
        }
    }
}
