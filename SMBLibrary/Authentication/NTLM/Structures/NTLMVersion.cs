/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary.Authentication.NTLM
{
    /// <summary>
    /// [MS-NLMP] 2.2.2.10 - VERSION
    /// </summary>
    public class NtlmVersion
    {
        public const int Length = 8;
        public const byte NTLMSSP_REVISION_W2K3 = 0x0F;

        public byte ProductMajorVersion;
        public byte ProductMinorVersion;
        public ushort ProductBuild;

        // Reserved - 3 bytes
        public byte NTLMRevisionCurrent;

        public NtlmVersion(byte majorVersion, byte minorVersion, ushort build, byte ntlmRevisionCurrent)
        {
            ProductMajorVersion = majorVersion;
            ProductMinorVersion = minorVersion;
            ProductBuild = build;
            NTLMRevisionCurrent = ntlmRevisionCurrent;
        }

        public NtlmVersion(byte[] buffer, int offset)
        {
            ProductMajorVersion = ByteReader.ReadByte(buffer, offset + 0);
            ProductMinorVersion = ByteReader.ReadByte(buffer, offset + 1);
            ProductBuild = LittleEndianConverter.ToUInt16(buffer, offset + 2);
            NTLMRevisionCurrent = ByteReader.ReadByte(buffer, offset + 7);
        }

        public void WriteBytes(byte[] buffer, int offset)
        {
            ByteWriter.WriteByte(buffer, offset + 0, ProductMajorVersion);
            ByteWriter.WriteByte(buffer, offset + 1, ProductMinorVersion);
            LittleEndianWriter.WriteUInt16(buffer, offset + 2, ProductBuild);
            ByteWriter.WriteByte(buffer, offset + 7, NTLMRevisionCurrent);
        }

        public override string ToString()
        {
            return $"{ProductMajorVersion}.{ProductMinorVersion}.{ProductBuild}";
        }

        public static NtlmVersion WindowsXP => new NtlmVersion(5, 1, 2600, NTLMSSP_REVISION_W2K3);

        public static NtlmVersion Server2003 => new NtlmVersion(5, 2, 3790, NTLMSSP_REVISION_W2K3);
    }
}