/* Copyright (C) 2012-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;

namespace Utilities
{
    public class BigEndianConverter
    {
        public static ushort ToUInt16(byte[] buffer, int offset)
        {
            return (ushort) ((buffer[offset + 0] << 8) | (buffer[offset + 1] << 0));
        }

        public static uint ToUInt32(byte[] buffer, int offset)
        {
            return (uint) ((buffer[offset + 0] << 24) | (buffer[offset + 1] << 16) | (buffer[offset + 2] << 8) | (buffer[offset + 3] << 0));
        }

        public static byte[] GetBytes(ushort value)
        {
            byte[] result = new byte[2];
            result[0] = (byte) ((value >> 8) & 0xFF);
            result[1] = (byte) ((value >> 0) & 0xFF);
            return result;
        }

        public static byte[] GetBytes(uint value)
        {
            byte[] result = new byte[4];
            result[0] = (byte) ((value >> 24) & 0xFF);
            result[1] = (byte) ((value >> 16) & 0xFF);
            result[2] = (byte) ((value >> 8) & 0xFF);
            result[3] = (byte) ((value >> 0) & 0xFF);

            return result;
        }
    }
}