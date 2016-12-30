using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Windows;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
using static global::Interop.BCrypt;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Windows
{
    internal static class BCryptHashHelper
    {
        internal unsafe static SafeBCryptHashHandle CreateHash(SafeBCryptAlgorithmHandle provider, byte[] key, Memory<byte>? buffer)
        {
            SafeBCryptHashHandle hashPtr;
            void* bufferPointer= null;
            int length = 0;
            if (buffer.HasValue)
            {
                length = buffer.Value.Length;
                if (!buffer.Value.TryGetPointer(out bufferPointer))
                {
                    throw new InvalidOperationException("Problem getting the pointer for a native memory block");
                }
            }
            if (key != null)
            {
                ExceptionHelper.CheckReturnCode(BCryptCreateHash(provider, out hashPtr, (IntPtr)bufferPointer, length, key, key.Length, 0));
            }
            else
            {
                ExceptionHelper.CheckReturnCode(BCryptCreateHash(provider, out hashPtr, (IntPtr)bufferPointer, length, null, 0, 0));
            }
            return hashPtr;
        }

        internal unsafe static void FinishHash(SafeBCryptHashHandle hash, Memory<byte> output)
        {
            void* bufferPointer;
            if (!output.TryGetPointer(out bufferPointer))
            {
                throw new InvalidOperationException("Problem getting the pointer for a native memory block");
            }
            ExceptionHelper.CheckReturnCode(BCryptFinishHash(hash, (IntPtr)bufferPointer, output.Length, 0));
        }

        internal unsafe static void FinishHash(SafeBCryptHashHandle hash, byte* buffer, int length)
        {
            ExceptionHelper.CheckReturnCode(BCryptFinishHash(hash, (IntPtr)buffer, length, 0));
        }

        internal unsafe static SafeBCryptHashHandle Duplicate(SafeBCryptHashHandle hash, Memory<byte> buffer)
        {
            void* pointer;
            if (!buffer.TryGetPointer(out pointer))
            {
                throw new InvalidOperationException("Problem getting the pointer for a memory block");
            }
            SafeBCryptHashHandle returnPtr;
            ExceptionHelper.CheckReturnCode(BCryptDuplicateHash(hash, out returnPtr, (IntPtr)pointer, buffer.Length, 0));
            return returnPtr;
        }

        internal unsafe static void HashData(SafeBCryptHashHandle hashHandle, byte* buffer, int length)
        {
            ExceptionHelper.CheckReturnCode(BCryptHashData(hashHandle, buffer, length, 0));
        }
    }
}
