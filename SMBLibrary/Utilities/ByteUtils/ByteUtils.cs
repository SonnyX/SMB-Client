/* Copyright (C) 2012-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.IO;

namespace Utilities
{
    public class ByteUtils
    {
        public static byte[] Concatenate(byte[] a, byte[] b)
        {
            byte[] result = new byte[a.Length + b.Length];
            Array.Copy(a, 0, result, 0, a.Length);
            Array.Copy(b, 0, result, a.Length, b.Length);
            return result;
        }

        public static bool AreByteArraysEqual(byte[] array1, byte[] array2)
        {
            if (array1.Length != array2.Length)
            {
                return false;
            }

            for (int index = 0; index < array1.Length; index++)
            {
                if (array1[index] != array2[index])
                {
                    return false;
                }
            }

            return true;
        }

        public static byte[] XOR(byte[] array1, int offset1, byte[] array2, int offset2, int length)
        {
            if (offset1 + length <= array1.Length && offset2 + length <= array2.Length)
            {
                byte[] result = new byte[length];
                for (int index = 0; index < length; index++)
                {
                    result[index] = (byte) (array1[offset1 + index] ^ array2[offset2 + index]);
                }

                return result;
            }

            throw new ArgumentOutOfRangeException();
        }
    }
}