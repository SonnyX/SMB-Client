/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary
{
    public abstract class FileSystemInformation
    {
        public abstract void WriteBytes(byte[] buffer, int offset);

        public byte[] GetBytes()
        {
            byte[] buffer = new byte[this.Length];
            WriteBytes(buffer, 0);
            return buffer;
        }

        public abstract FileSystemInformationClass FileSystemInformationClass
        {
            get;
        }

        public abstract int Length
        {
            get;
        }

        public static FileSystemInformation GetFileSystemInformation(byte[] buffer, int offset, FileSystemInformationClass informationClass)
        {
            return informationClass switch
            {
                FileSystemInformationClass.FileFsVolumeInformation => new FileFsVolumeInformation(buffer, offset),
                FileSystemInformationClass.FileFsSizeInformation => new FileFsSizeInformation(buffer, offset),
                FileSystemInformationClass.FileFsDeviceInformation => new FileFsDeviceInformation(buffer, offset),
                FileSystemInformationClass.FileFsAttributeInformation => new FileFsAttributeInformation(buffer, offset),
                FileSystemInformationClass.FileFsControlInformation => new FileFsControlInformation(buffer, offset),
                FileSystemInformationClass.FileFsFullSizeInformation => new FileFsFullSizeInformation(buffer, offset),
                FileSystemInformationClass.FileFsObjectIdInformation => new FileFsObjectIdInformation(buffer, offset),
                FileSystemInformationClass.FileFsSectorSizeInformation => new FileFsSectorSizeInformation(buffer,
                    offset),
                _ => throw new UnsupportedInformationLevelException()
            };
        }
    }
}