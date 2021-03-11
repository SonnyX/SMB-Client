/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;

namespace SMBLibrary.SMB1
{
    public class FindInformationHelper
    {
        /// <exception cref="UnsupportedInformationLevelException"></exception>
        public static FileInformationClass ToFileInformationClass(FindInformationLevel informationLevel)
        {
            return informationLevel switch
            {
                FindInformationLevel.SMB_FIND_FILE_DIRECTORY_INFO => FileInformationClass.FileDirectoryInformation,
                FindInformationLevel.SMB_FIND_FILE_FULL_DIRECTORY_INFO => FileInformationClass.FileFullDirectoryInformation,
                FindInformationLevel.SMB_FIND_FILE_NAMES_INFO => FileInformationClass.FileNamesInformation,
                FindInformationLevel.SMB_FIND_FILE_BOTH_DIRECTORY_INFO => FileInformationClass.FileBothDirectoryInformation,
                FindInformationLevel.SMB_FIND_FILE_ID_FULL_DIRECTORY_INFO => FileInformationClass.FileIdFullDirectoryInformation,
                FindInformationLevel.SMB_FIND_FILE_ID_BOTH_DIRECTORY_INFO => FileInformationClass.FileIdBothDirectoryInformation,
                _ => throw new UnsupportedInformationLevelException()
            };
        }

        /// <exception cref="UnsupportedInformationLevelException"></exception>
        public static FindInformationList ToFindInformationList(List<QueryDirectoryFileInformation> entries, bool isUnicode, int maxLength)
        {
            FindInformationList result = new FindInformationList();
            int pageLength = 0;
            foreach (QueryDirectoryFileInformation entry in entries)
            {
                FindInformation infoEntry = ToFindInformation(entry);
                int entryLength = infoEntry.GetLength(isUnicode);
                if (pageLength + entryLength <= maxLength)
                {
                    result.Add(infoEntry);
                    pageLength += entryLength;
                }
                else
                {
                    break;
                }
            }
            return result;
        }

        /// <exception cref="UnsupportedInformationLevelException"></exception>
        public static FindInformation ToFindInformation(QueryDirectoryFileInformation fileInformation)
        {
            switch (fileInformation)
            {
                case FileDirectoryInformation fileDirectoryInfo:
                {
                    FindFileDirectoryInfo result = new FindFileDirectoryInfo
                    {
                        FileIndex = fileDirectoryInfo.FileIndex,
                        CreationTime = fileDirectoryInfo.CreationTime,
                        LastAccessTime = fileDirectoryInfo.LastAccessTime,
                        LastWriteTime = fileDirectoryInfo.LastWriteTime,
                        LastAttrChangeTime = fileDirectoryInfo.LastWriteTime,
                        EndOfFile = fileDirectoryInfo.EndOfFile,
                        AllocationSize = fileDirectoryInfo.AllocationSize,
                        ExtFileAttributes = (ExtendedFileAttributes)fileDirectoryInfo.FileAttributes,
                        FileName = fileDirectoryInfo.FileName
                    };
                    return result;
                }
                case FileFullDirectoryInformation fileFullDirectoryInfo:
                {
                    FindFileFullDirectoryInfo result = new FindFileFullDirectoryInfo
                    {
                        FileIndex = fileFullDirectoryInfo.FileIndex,
                        CreationTime = fileFullDirectoryInfo.CreationTime,
                        LastAccessTime = fileFullDirectoryInfo.LastAccessTime,
                        LastWriteTime = fileFullDirectoryInfo.LastWriteTime,
                        LastAttrChangeTime = fileFullDirectoryInfo.LastWriteTime,
                        EndOfFile = fileFullDirectoryInfo.EndOfFile,
                        AllocationSize = fileFullDirectoryInfo.AllocationSize,
                        ExtFileAttributes = (ExtendedFileAttributes)fileFullDirectoryInfo.FileAttributes,
                        EASize = fileFullDirectoryInfo.EaSize,
                        FileName = fileFullDirectoryInfo.FileName
                    };
                    return result;
                }
                case FileNamesInformation fileNamesInfo:
                {
                    FindFileNamesInfo result = new FindFileNamesInfo
                    {
                        FileIndex = fileNamesInfo.FileIndex,
                        FileName = fileNamesInfo.FileName
                    };
                    return result;
                }
                case FileBothDirectoryInformation fileBothDirectoryInfo:
                {
                    FindFileBothDirectoryInfo result = new FindFileBothDirectoryInfo
                    {
                        FileIndex = fileBothDirectoryInfo.FileIndex,
                        CreationTime = fileBothDirectoryInfo.CreationTime,
                        LastAccessTime = fileBothDirectoryInfo.LastAccessTime,
                        LastWriteTime = fileBothDirectoryInfo.LastWriteTime,
                        LastChangeTime = fileBothDirectoryInfo.LastWriteTime,
                        EndOfFile = fileBothDirectoryInfo.EndOfFile,
                        AllocationSize = fileBothDirectoryInfo.AllocationSize,
                        ExtFileAttributes = (ExtendedFileAttributes)fileBothDirectoryInfo.FileAttributes,
                        EASize = fileBothDirectoryInfo.EaSize,
                        Reserved = fileBothDirectoryInfo.Reserved,
                        ShortName = fileBothDirectoryInfo.ShortName,
                        FileName = fileBothDirectoryInfo.FileName
                    };
                    return result;
                }
                case FileIdFullDirectoryInformation fileIDFullDirectoryInfo:
                {
                    FindFileIDFullDirectoryInfo result = new FindFileIDFullDirectoryInfo
                    {
                        FileIndex = fileIDFullDirectoryInfo.FileIndex,
                        CreationTime = fileIDFullDirectoryInfo.CreationTime,
                        LastAccessTime = fileIDFullDirectoryInfo.LastAccessTime,
                        LastWriteTime = fileIDFullDirectoryInfo.LastWriteTime,
                        LastAttrChangeTime = fileIDFullDirectoryInfo.LastWriteTime,
                        EndOfFile = fileIDFullDirectoryInfo.EndOfFile,
                        AllocationSize = fileIDFullDirectoryInfo.AllocationSize,
                        ExtFileAttributes = (ExtendedFileAttributes)fileIDFullDirectoryInfo.FileAttributes,
                        EASize = fileIDFullDirectoryInfo.EaSize,
                        Reserved = fileIDFullDirectoryInfo.Reserved,
                        FileID = fileIDFullDirectoryInfo.FileId,
                        FileName = fileIDFullDirectoryInfo.FileName
                    };
                    return result;
                }
                case FileIdBothDirectoryInformation fileIDBothDirectoryInfo:
                {
                    FindFileIDBothDirectoryInfo result = new FindFileIDBothDirectoryInfo
                    {
                        FileIndex = fileIDBothDirectoryInfo.FileIndex,
                        CreationTime = fileIDBothDirectoryInfo.CreationTime,
                        LastAccessTime = fileIDBothDirectoryInfo.LastAccessTime,
                        LastWriteTime = fileIDBothDirectoryInfo.LastWriteTime,
                        LastChangeTime = fileIDBothDirectoryInfo.LastWriteTime,
                        EndOfFile = fileIDBothDirectoryInfo.EndOfFile,
                        AllocationSize = fileIDBothDirectoryInfo.AllocationSize,
                        ExtFileAttributes = (ExtendedFileAttributes)fileIDBothDirectoryInfo.FileAttributes,
                        EASize = fileIDBothDirectoryInfo.EaSize,
                        Reserved = fileIDBothDirectoryInfo.Reserved1,
                        ShortName = fileIDBothDirectoryInfo.ShortName,
                        Reserved2 = fileIDBothDirectoryInfo.Reserved2,
                        FileID = fileIDBothDirectoryInfo.FileId,
                        FileName = fileIDBothDirectoryInfo.FileName
                    };
                    return result;
                }
                default:
                    throw new NotImplementedException();
            }
        }
    }
}