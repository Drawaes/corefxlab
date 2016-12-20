﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Windows
{
    internal unsafe static class InteropHash
    {
        private const string Dll = "Bcrypt.dll";

        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private extern static NTResult BCryptCreateHash(IntPtr hAlgorithm, out IntPtr phHash, void* stateBuffer, int hashBufferLength, void* secretBuffer, int secretLength, uint dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private extern static NTResult BCryptHashData(IntPtr hashHandle, void* inputBuffer, int inputLength, uint dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private extern static NTResult BCryptDestroyHash(IntPtr hashHandle);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private extern static NTResult BCryptDuplicateHash(IntPtr hHash, out IntPtr phNewHash, void* pbHashObject, int cbHashObject, uint dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private extern static NTResult BCryptFinishHash(IntPtr hHash, void* pbOutput, int cbOutput, uint dwFlags);
        [DllImport(Dll, ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        internal extern static NTResult BCryptHash(IntPtr hAlgorithm, void* pbSecret, int cbSecret, void* pbInput, int cbInput, void* pbOutput, int cbOutput);

        public static void DestroyHash(IntPtr hash) => ExceptionHelper.CheckReturnCode(BCryptDestroyHash(hash));

        public static IntPtr CreateHash(IntPtr provider, byte[] key, Memory<byte> buffer)
        {
            IntPtr hashPtr;
            void* bufferPointer;
            if (!buffer.TryGetPointer(out bufferPointer))
            {
                throw new InvalidOperationException("Problem getting the pointer for a native memory block");
            }
            if (key != null)
            {
                fixed (void* keyPointer = key)
                {
                    ExceptionHelper.CheckReturnCode(BCryptCreateHash(provider, out hashPtr, bufferPointer, buffer.Length, keyPointer, key.Length, 0));
                }
            }
            else
            {
                ExceptionHelper.CheckReturnCode(BCryptCreateHash(provider, out hashPtr, bufferPointer, buffer.Length, null, 0, 0));
            }
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

        public static void FinishHash(IntPtr hash, byte* buffer, int length)
        {
            ExceptionHelper.CheckReturnCode(BCryptFinishHash(hash, buffer, length, 0));
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

        internal static void HashData(IntPtr hashHandle, byte* buffer, int length)
        {
            ExceptionHelper.CheckReturnCode(BCryptHashData(hashHandle, buffer, length, 0));
        }

        public static void HashData(IntPtr hash, Memory<byte> buffer)
        {
            void* pointer;
            if (!buffer.TryGetPointer(out pointer))
            {
                ArraySegment<byte> arrayBuffer;
                buffer.TryGetArray(out arrayBuffer);
                fixed (byte* arrayPtr = arrayBuffer.Array)
                {
                    var frontPtr = arrayPtr + arrayBuffer.Offset;
                    ExceptionHelper.CheckReturnCode(BCryptHashData(hash, frontPtr, buffer.Length, 0));
                }
            }
            else
            {
                ExceptionHelper.CheckReturnCode(BCryptHashData(hash, pointer, buffer.Length, 0));
            }
        }

    }
}
