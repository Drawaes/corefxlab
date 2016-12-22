using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.BulkCiphers
{
    internal static class BulkCipherExtensions
    {
        public static IBulkCipherProvider GetCipher(this IBulkCipherPal pal, string cipherType)
        {
            BulkCipherType cipher;
            if (!Enum.TryParse(cipherType, out cipher))
            {
                return null;
            }
            return pal.GetCipher(cipher);
        }
    }
}
