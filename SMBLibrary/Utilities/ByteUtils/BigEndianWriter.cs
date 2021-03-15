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
    public class BigEndianWriter
    {
        public static void WriteUInt16(byte[] buffer, int offset, ushort value)
        {
            byte[] bytes = BigEndianConverter.GetBytes(value);
            Array.Copy(bytes, 0, buffer, offset, bytes.Length);
        }

        public static void WriteUInt16(byte[] buffer, ref int offset, ushort value)
        {
            WriteUInt16(buffer, offset, value);
            offset += 2;
        }

        public static void WriteUInt32(byte[] buffer, int offset, uint value)
        {
            byte[] bytes = BigEndianConverter.GetBytes(value);
            Array.Copy(bytes, 0, buffer, offset, bytes.Length);
        }

        public static void WriteUInt32(byte[] buffer, ref int offset, uint value)
        {
            WriteUInt32(buffer, offset, value);
            offset += 4;
        }

        public static void WriteUInt16(Stream stream, ushort value)
        {
            byte[] bytes = BigEndianConverter.GetBytes(value);
            stream.Write(bytes, 0, bytes.Length);
        }

        public static void WriteUInt32(Stream stream, uint value)
        {
            byte[] bytes = BigEndianConverter.GetBytes(value);
            stream.Write(bytes, 0, bytes.Length);
        }
    }
}