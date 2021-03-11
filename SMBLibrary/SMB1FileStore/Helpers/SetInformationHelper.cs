/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;

namespace SMBLibrary.SMB1
{
    public class SetInformationHelper
    {
        public static FileInformation ToFileInformation(SetInformation information)
        {
            switch (information)
            {
                case SetFileBasicInfo info:
                    {
                        SetFileBasicInfo basicInfo = info;
                        FileBasicInformation fileBasicInfo = new FileBasicInformation
                        {
                            CreationTime = basicInfo.CreationTime,
                            LastAccessTime = basicInfo.LastAccessTime,
                            LastWriteTime = basicInfo.LastWriteTime,
                            ChangeTime = basicInfo.LastChangeTime,
                            FileAttributes = (FileAttributes)basicInfo.ExtFileAttributes,
                            Reserved = basicInfo.Reserved
                        };
                        return fileBasicInfo;
                    }
                case SetFileDispositionInfo info:
                    {
                        FileDispositionInformation fileDispositionInfo = new FileDispositionInformation
                        {
                            DeletePending = info.DeletePending
                        };
                        return fileDispositionInfo;
                    }
                case SetFileAllocationInfo info:
                    {
                        // This information level is used to set the file length in bytes.
                        // Note: the input will NOT be a multiple of the cluster size / bytes per sector.
                        FileAllocationInformation fileAllocationInfo = new FileAllocationInformation
                        {
                            AllocationSize = info.AllocationSize
                        };
                        return fileAllocationInfo;
                    }
                case SetFileEndOfFileInfo info:
                    {
                        FileEndOfFileInformation fileEndOfFileInfo = new FileEndOfFileInformation
                        {
                            EndOfFile = info.EndOfFile
                        };
                        return fileEndOfFileInfo;
                    }
                default:
                    throw new NotImplementedException();
            }
        }
    }
}