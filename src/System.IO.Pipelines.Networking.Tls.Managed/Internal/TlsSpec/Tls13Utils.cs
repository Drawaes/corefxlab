using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Hash;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.TlsSpec
{
    internal class Tls13Utils
    {
        const string _labelPrefix = "TLS 1.3, ";

        public static byte[] DerviceSecret(IHashProvider provider, byte[] secret, string label, byte[] messageHash)
        {
            return HKDFExpandLabel(provider, secret, label, messageHash, provider.HashLength);
        }

        public static byte[] HKDFExpandLabel(IHashProvider provider, byte[] secret, string label, byte[] messageHash, int length)
        {
            int currentIndex =  0;
            byte[] hkdfeLabel = new byte[_labelPrefix.Length + label.Length + 1+1+2];
            var len = BitConverter.GetBytes((ushort)messageHash.Length);
            len.CopyTo(hkdfeLabel,currentIndex);
            currentIndex += 2;
            hkdfeLabel[currentIndex] =(byte) (_labelPrefix.Length + label.Length);
            currentIndex ++;
            var lab = Encoding.ASCII.GetBytes(_labelPrefix + label);
            lab.CopyTo(hkdfeLabel,currentIndex);
            currentIndex += lab.Length;
            hkdfeLabel[currentIndex] = (byte)messageHash.Length;
            currentIndex ++;
            messageHash.CopyTo(hkdfeLabel,currentIndex);

            return HKDFExpand(provider, secret, hkdfeLabel, length);
        }

        public unsafe static byte[] HKDFExpand(IHashProvider provider,byte[] PRK, byte[] info, int L)
        {
            var N = (int)Math.Ceiling(L /  (double)provider.HashLength);
            var T = new byte[provider.HashLength + info.Length + 1];
            var output = new byte[provider.HashLength];
            var returnData = new byte[L];
            var returnSpan = new Span<byte>(returnData);

            fixed (byte* prk = PRK)
            fixed (byte* tPtr = T)
            fixed (byte* oPtr = output)
            {
                var tSpan = new Span<byte>(tPtr, T.Length);
                info.CopyTo(tSpan);
                tSpan.Slice(info.Length).Write((byte)1);
                provider.HmacValue(oPtr, output.Length, prk, PRK.Length, tPtr, provider.HashLength + 1);
                int amountToCopy = Math.Min(returnSpan.Length, output.Length);
                output.Slice(0,amountToCopy).CopyTo(returnSpan);
                returnSpan = returnSpan.Slice(amountToCopy);
                info.CopyTo(tSpan.Slice(provider.HashLength));
                byte index = 2;
                var indexSpan = tSpan.Slice(tSpan.Length -1);

                while (true)
                {
                    if(returnSpan.Length == 0)
                    {
                        return returnData;
                    }
                    indexSpan.Write(index);
                    output.CopyTo(tSpan);
                    provider.HmacValue(oPtr, output.Length, prk, PRK.Length, tPtr, T.Length);
                    amountToCopy = Math.Min(returnSpan.Length, output.Length);
                    output.Slice(0, amountToCopy).CopyTo(returnSpan);
                    returnSpan = returnSpan.Slice(amountToCopy);
                    index ++;
                }
            }
        }
    }
}
