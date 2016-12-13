using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Windows
{
    internal unsafe static class InteropHash
    {
        private const string Dll = "Bcrypt.dll";

        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private extern static ReturnCodes BCryptCreateHash(IntPtr hAlgorithm, out IntPtr phHash, void* stateBuffer, int hashBufferLength, void* secretBuffer, int secretLength, uint dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private extern static ReturnCodes BCryptHashData(IntPtr hashHandle, void* inputBuffer, int inputLength, uint dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private extern static ReturnCodes BCryptDestroyHash(IntPtr hashHandle);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private extern static ReturnCodes BCryptDuplicateHash(IntPtr hHash, out IntPtr phNewHash, void* pbHashObject, int cbHashObject, uint dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private extern static ReturnCodes BCryptFinishHash(IntPtr hHash, void* pbOutput, int cbOutput, uint dwFlags);

        public static void DestroyHash(IntPtr hash) => ExceptionHelper.CheckReturnCode(BCryptDestroyHash(hash));

        public static IntPtr CreateHash(IntPtr provider, Memory<byte> buffer)
        {
            IntPtr hashPtr;
            void* bufferPointer;
            if (!buffer.TryGetPointer(out bufferPointer))
            {
                throw new InvalidOperationException("Problem getting the pointer for a native memory block");
            }
            ExceptionHelper.CheckReturnCode(BCryptCreateHash(provider, out hashPtr, bufferPointer, buffer.Length, null, 0, 0));
            return hashPtr;
        }

        public static void FinishHash(IntPtr hash, Memory<byte> output)
        {
            void* bufferPointer;
            if (!output.TryGetPointer(out bufferPointer))
            {
                throw new InvalidOperationException("Problem getting the pointer for a native memory block");
            }
            ExceptionHelper.CheckReturnCode(BCryptFinishHash(hash, bufferPointer, output.Length, 0));
        }

        public static IntPtr Duplicate(IntPtr hash, Memory<byte> buffer)
        {
            void* pointer;
            if (!buffer.TryGetPointer(out pointer))
            {
                throw new InvalidOperationException("Problem getting the pointer for a memory block");
            }
            IntPtr returnPtr;
            ExceptionHelper.CheckReturnCode(BCryptDuplicateHash(hash, out returnPtr, pointer, buffer.Length, 0));
            return returnPtr;
        }

        public static void HashData(IntPtr hash, Memory<byte> buffer)
        {
            void* pointer;
            if (!buffer.TryGetPointer(out pointer))
            {
                throw new InvalidOperationException("Problem getting the pointer for a memory block");
            }
            ExceptionHelper.CheckReturnCode(BCryptHashData(hash, pointer, buffer.Length, 0));
        }

    }
}
