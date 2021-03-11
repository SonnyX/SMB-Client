/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;

namespace SMBLibrary.SMB1
{
    public class QueryFSInformationHelper
    {
        /// <exception cref="UnsupportedInformationLevelException"></exception>
        public static FileSystemInformationClass ToFileSystemInformationClass(QueryFSInformationLevel informationLevel)
        {
            return informationLevel switch
            {
                QueryFSInformationLevel.SMB_QUERY_FS_VOLUME_INFO => FileSystemInformationClass.FileFsVolumeInformation,
                QueryFSInformationLevel.SMB_QUERY_FS_SIZE_INFO => FileSystemInformationClass.FileFsSizeInformation,
                QueryFSInformationLevel.SMB_QUERY_FS_DEVICE_INFO => FileSystemInformationClass.FileFsDeviceInformation,
                QueryFSInformationLevel.SMB_QUERY_FS_ATTRIBUTE_INFO => FileSystemInformationClass
                    .FileFsAttributeInformation,
                _ => throw new UnsupportedInformationLevelException()
            };
        }

        public static QueryFSInformation FromFileSystemInformation(FileSystemInformation fsInfo)
        {
            switch (fsInfo)
            {
                case FileFsVolumeInformation volumeInfo:
                {
                    QueryFSVolumeInfo result = new QueryFSVolumeInfo
                    {
                        VolumeCreationTime = volumeInfo.VolumeCreationTime,
                        SerialNumber = volumeInfo.VolumeSerialNumber,
                        VolumeLabel = volumeInfo.VolumeLabel
                    };
                    return result;
                }
                case FileFsSizeInformation fsSizeInfo:
                {
                    QueryFSSizeInfo result = new QueryFSSizeInfo
                    {
                        TotalAllocationUnits = fsSizeInfo.TotalAllocationUnits,
                        TotalFreeAllocationUnits = fsSizeInfo.AvailableAllocationUnits,
                        BytesPerSector = fsSizeInfo.BytesPerSector,
                        SectorsPerAllocationUnit = fsSizeInfo.SectorsPerAllocationUnit
                    };
                    return result;
                }
                case FileFsDeviceInformation fsDeviceInfo:
                {
                    QueryFSDeviceInfo result = new QueryFSDeviceInfo
                    {
                        DeviceType = fsDeviceInfo.DeviceType,
                        DeviceCharacteristics = fsDeviceInfo.Characteristics
                    };
                    return result;
                }
                case FileFsAttributeInformation fsAttributeInfo:
                {
                    QueryFSAttibuteInfo result = new QueryFSAttibuteInfo
                    {
                        FileSystemAttributes = fsAttributeInfo.FileSystemAttributes,
                        MaxFileNameLengthInBytes = fsAttributeInfo.MaximumComponentNameLength,
                        FileSystemName = fsAttributeInfo.FileSystemName
                    };
                    return result;
                }
                default:
                    throw new NotImplementedException();
            }
        }
    }
}