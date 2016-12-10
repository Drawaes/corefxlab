using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Internal.ManagedTls
{
    public enum ReturnCodes : uint
    {
        STATUS_SUCCESS = 0x00000000,
        STATUS_INVALID_PARAMETER = 0xC000000D,
        STATUS_NO_MEMORY = 0xC0000017,
        STATUS_INVALID_EA_FLAG = 0x80000015,
        STATUS_CERTIFICATE_NOT_FOUND = 0x80090016,
        NTE_NO_MORE_ITEMS = 0x8009002A,
        MEM_E_INVALID_LINK = 0x80080010, //An allocation chain contained an invalid linkpointer
        NTE_BAD_FLAGS = 0x80090009, //Invalid flags specified.
        NTE_PERM = 0x80090010, //Access denied.
        AuthenticationTagMismatch = 0xC000A002,
        STATUS_NOT_SUPPORTED = 0xc00000bb,

    }
}
