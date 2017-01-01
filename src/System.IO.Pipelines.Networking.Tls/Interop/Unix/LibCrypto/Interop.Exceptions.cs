using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

internal partial class Interop
{
    internal partial class LibCrypto
    {
		internal static int ThrowOnError(int returnCode)
        {
			if(returnCode != 1)
            {
				throw new NotImplementedException();
            }
            return returnCode;
        }
        
        internal static IntPtr ThrowOnError(IntPtr returnCode)
        {
            if(returnCode.ToInt64() < 1)
            {
                throw new NotImplementedException();
            }
            return returnCode;
        }
    }
}
