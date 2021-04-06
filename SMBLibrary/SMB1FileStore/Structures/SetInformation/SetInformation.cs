/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary.SMB1
{
    public abstract class SetInformation
    {
        public abstract byte[] GetBytes();

        public abstract SetInformationLevel InformationLevel { get; }

        public static SetInformation GetSetInformation(byte[] buffer, SetInformationLevel informationLevel)
        {
            return informationLevel switch
            {
                SetInformationLevel.SMB_SET_FILE_BASIC_INFO => new SetFileBasicInfo(buffer),
                SetInformationLevel.SMB_SET_FILE_DISPOSITION_INFO => new SetFileDispositionInfo(buffer),
                SetInformationLevel.SMB_SET_FILE_ALLOCATION_INFO => new SetFileAllocationInfo(buffer),
                SetInformationLevel.SMB_SET_FILE_END_OF_FILE_INFO => new SetFileEndOfFileInfo(buffer),
                _ => throw new UnsupportedInformationLevelException()
            };
        }
    }
}