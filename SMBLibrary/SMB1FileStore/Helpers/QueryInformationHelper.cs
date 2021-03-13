/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;

namespace SMBLibrary.SMB1
{
    public class QueryInformationHelper
    {
        /// <exception cref="UnsupportedInformationLevelException"></exception>
        public static FileInformationClass ToFileInformationClass(QueryInformationLevel informationLevel)
        {
            return informationLevel switch
            {
                QueryInformationLevel.SMB_QUERY_FILE_BASIC_INFO => FileInformationClass.FileBasicInformation,
                QueryInformationLevel.SMB_QUERY_FILE_STANDARD_INFO => FileInformationClass.FileStandardInformation,
                QueryInformationLevel.SMB_QUERY_FILE_EA_INFO => FileInformationClass.FileEaInformation,
                QueryInformationLevel.SMB_QUERY_FILE_NAME_INFO => FileInformationClass.FileNameInformation,
                QueryInformationLevel.SMB_QUERY_FILE_ALL_INFO => FileInformationClass.FileAllInformation,
                QueryInformationLevel.SMB_QUERY_FILE_ALT_NAME_INFO => FileInformationClass.FileAlternateNameInformation,
                QueryInformationLevel.SMB_QUERY_FILE_STREAM_INFO => FileInformationClass.FileStreamInformation,
                QueryInformationLevel.SMB_QUERY_FILE_COMPRESSION_INFO =>
                    FileInformationClass.FileCompressionInformation,
                _ => throw new UnsupportedInformationLevelException()
            };
        }

        public static QueryInformation FromFileInformation(FileInformation fileInformation)
        {
            switch (fileInformation)
            {
                case FileAlternateNameInformation information:
                    {
                        FileAlternateNameInformation fileAltNameInfo = information;
                        QueryFileAltNameInfo result = new QueryFileAltNameInfo
                        {
                            FileName = fileAltNameInfo.FileName
                        };
                        return result;
                    }
                case FileBasicInformation information:
                    {
                        FileBasicInformation fileBasicInfo = information;
                        QueryFileBasicInfo result = new QueryFileBasicInfo
                        {
                            CreationTime = fileBasicInfo.CreationTime,
                            LastAccessTime = fileBasicInfo.LastAccessTime,
                            LastWriteTime = fileBasicInfo.LastWriteTime,
                            LastChangeTime = fileBasicInfo.ChangeTime,
                            ExtFileAttributes = (ExtendedFileAttributes)fileBasicInfo.FileAttributes
                        };
                        return result;
                    }
                case FileStandardInformation information:
                    {
                        FileStandardInformation fileStandardInfo = information;
                        QueryFileStandardInfo result = new QueryFileStandardInfo
                        {
                            AllocationSize = fileStandardInfo.AllocationSize,
                            EndOfFile = fileStandardInfo.EndOfFile,
                            DeletePending = fileStandardInfo.DeletePending,
                            Directory = fileStandardInfo.Directory
                        };
                        return result;
                    }
                case FileEaInformation information:
                    {
                        FileEaInformation fileEAInfo = information;
                        QueryFileEaInfo result = new QueryFileEaInfo
                        {
                            EaSize = fileEAInfo.EaSize
                        };
                        return result;
                    }
                case FileNameInformation information:
                    {
                        FileNameInformation fileNameInfo = information;
                        QueryFileNameInfo result = new QueryFileNameInfo
                        {
                            FileName = fileNameInfo.FileName
                        };
                        return result;
                    }
                case FileAllInformation information:
                    {
                        FileAllInformation fileAllInfo = information;
                        QueryFileAllInfo result = new QueryFileAllInfo
                        {
                            CreationTime = fileAllInfo.BasicInformation.CreationTime,
                            LastAccessTime = fileAllInfo.BasicInformation.LastAccessTime,
                            LastWriteTime = fileAllInfo.BasicInformation.LastWriteTime,
                            LastChangeTime = fileAllInfo.BasicInformation.ChangeTime,
                            ExtFileAttributes = (ExtendedFileAttributes)fileAllInfo.BasicInformation.FileAttributes,
                            AllocationSize = fileAllInfo.StandardInformation.AllocationSize,
                            EndOfFile = fileAllInfo.StandardInformation.EndOfFile,
                            DeletePending = fileAllInfo.StandardInformation.DeletePending,
                            Directory = fileAllInfo.StandardInformation.Directory,
                            EaSize = fileAllInfo.EaInformation.EaSize,
                            FileName = fileAllInfo.NameInformation.FileName
                        };
                        return result;
                    }
                case FileStreamInformation information:
                    {
                        FileStreamInformation fileStreamInfo = information;
                        QueryFileStreamInfo result = new QueryFileStreamInfo();
                        result.Entries.AddRange(fileStreamInfo.Entries);
                        return result;
                    }
                case FileCompressionInformation information:
                    {
                        FileCompressionInformation fileCompressionInfo = information;
                        QueryFileCompressionInfo result = new QueryFileCompressionInfo
                        {
                            CompressedFileSize = fileCompressionInfo.CompressedFileSize,
                            CompressionFormat = fileCompressionInfo.CompressionFormat,
                            CompressionUnitShift = fileCompressionInfo.CompressionUnitShift,
                            ChunkShift = fileCompressionInfo.ChunkShift,
                            ClusterShift = fileCompressionInfo.ClusterShift,
                            Reserved = fileCompressionInfo.Reserved
                        };
                        return result;
                    }
                default:
                    throw new NotImplementedException();
            }
        }

        /// <exception cref="UnsupportedInformationLevelException"></exception>
        public static QueryInformationLevel ToFileInformationLevel(FileInformationClass informationClass)
        {
            return informationClass switch
            {
                FileInformationClass.FileBasicInformation => QueryInformationLevel.SMB_QUERY_FILE_BASIC_INFO,
                FileInformationClass.FileStandardInformation => QueryInformationLevel.SMB_QUERY_FILE_STANDARD_INFO,
                FileInformationClass.FileEaInformation => QueryInformationLevel.SMB_QUERY_FILE_EA_INFO,
                FileInformationClass.FileNameInformation => QueryInformationLevel.SMB_QUERY_FILE_NAME_INFO,
                FileInformationClass.FileAllInformation => QueryInformationLevel.SMB_QUERY_FILE_ALL_INFO,
                FileInformationClass.FileAlternateNameInformation => QueryInformationLevel.SMB_QUERY_FILE_ALT_NAME_INFO,
                FileInformationClass.FileStreamInformation => QueryInformationLevel.SMB_QUERY_FILE_STREAM_INFO,
                FileInformationClass.FileCompressionInformation =>
                    QueryInformationLevel.SMB_QUERY_FILE_COMPRESSION_INFO,
                _ => throw new UnsupportedInformationLevelException()
            };
        }

        public static FileInformation ToFileInformation(QueryInformation? queryInformation)
        {
            switch (queryInformation)
            {
                case QueryFileBasicInfo info:
                    {
                        QueryFileBasicInfo queryFileBasicInfo = info;
                        FileBasicInformation result = new FileBasicInformation
                        {
                            CreationTime = queryFileBasicInfo.CreationTime,
                            LastAccessTime = queryFileBasicInfo.LastAccessTime,
                            LastWriteTime = queryFileBasicInfo.LastWriteTime,
                            ChangeTime = queryFileBasicInfo.LastChangeTime,
                            FileAttributes = (FileAttributes)queryFileBasicInfo.ExtFileAttributes
                        };
                        return result;
                    }
                case QueryFileStandardInfo info:
                    {
                        QueryFileStandardInfo queryFileStandardInfo = info;
                        FileStandardInformation result = new FileStandardInformation
                        {
                            AllocationSize = queryFileStandardInfo.AllocationSize,
                            EndOfFile = queryFileStandardInfo.EndOfFile,
                            DeletePending = queryFileStandardInfo.DeletePending,
                            Directory = queryFileStandardInfo.Directory
                        };
                        return result;
                    }
                case QueryFileEaInfo info:
                    {
                        QueryFileEaInfo queryFileEaInfo = info;
                        FileEaInformation result = new FileEaInformation
                        {
                            EaSize = queryFileEaInfo.EaSize
                        };
                        return result;
                    }
                case QueryFileNameInfo info:
                    {
                        QueryFileNameInfo queryFileNameInfo = info;
                        FileNameInformation result = new FileNameInformation
                        {
                            FileName = queryFileNameInfo.FileName
                        };
                        return result;
                    }
                case QueryFileAllInfo info:
                    {
                        QueryFileAllInfo queryFileAllInfo = info;
                        FileAllInformation result = new FileAllInformation();
                        result.BasicInformation.CreationTime = queryFileAllInfo.CreationTime;
                        result.BasicInformation.LastAccessTime = queryFileAllInfo.LastAccessTime;
                        result.BasicInformation.LastWriteTime = queryFileAllInfo.LastWriteTime;
                        result.BasicInformation.ChangeTime = queryFileAllInfo.LastChangeTime;
                        result.BasicInformation.FileAttributes = (FileAttributes)queryFileAllInfo.ExtFileAttributes;
                        result.StandardInformation.AllocationSize = queryFileAllInfo.AllocationSize;
                        result.StandardInformation.EndOfFile = queryFileAllInfo.EndOfFile;
                        result.StandardInformation.DeletePending = queryFileAllInfo.DeletePending;
                        result.StandardInformation.Directory = queryFileAllInfo.Directory;
                        result.EaInformation.EaSize = queryFileAllInfo.EaSize;
                        result.NameInformation.FileName = queryFileAllInfo.FileName;
                        return result;
                    }
                case QueryFileAltNameInfo info:
                    {
                        QueryFileAltNameInfo queryFileAltNameInfo = info;
                        FileAlternateNameInformation result = new FileAlternateNameInformation
                        {
                            FileName = queryFileAltNameInfo.FileName
                        };
                        return result;
                    }
                case QueryFileStreamInfo info:
                    {
                        QueryFileStreamInfo queryFileStreamInfo = info;
                        FileStreamInformation result = new FileStreamInformation();
                        result.Entries.AddRange(queryFileStreamInfo.Entries);
                        return result;
                    }
                case QueryFileCompressionInfo info:
                    {
                        QueryFileCompressionInfo queryFileCompressionInfo = info;
                        FileCompressionInformation result = new FileCompressionInformation
                        {
                            CompressedFileSize = queryFileCompressionInfo.CompressedFileSize,
                            CompressionFormat = queryFileCompressionInfo.CompressionFormat,
                            CompressionUnitShift = queryFileCompressionInfo.CompressionUnitShift,
                            ChunkShift = queryFileCompressionInfo.ChunkShift,
                            ClusterShift = queryFileCompressionInfo.ClusterShift,
                            Reserved = queryFileCompressionInfo.Reserved
                        };
                        return result;
                    }
                default:
                    throw new NotImplementedException();
            }
        }
    }
}