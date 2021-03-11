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
            if (fsInfo is FileFsVolumeInformation)
            {
                FileFsVolumeInformation volumeInfo = (FileFsVolumeInformation)fsInfo;
                QueryFSVolumeInfo result = new QueryFSVolumeInfo
                {
                    VolumeCreationTime = volumeInfo.VolumeCreationTime,
                    SerialNumber = volumeInfo.VolumeSerialNumber,
                    VolumeLabel = volumeInfo.VolumeLabel
                };
                return result;
            }

            if (fsInfo is FileFsSizeInformation)
            {
                FileFsSizeInformation fsSizeInfo = (FileFsSizeInformation)fsInfo;
                QueryFSSizeInfo result = new QueryFSSizeInfo
                {
                    TotalAllocationUnits = fsSizeInfo.TotalAllocationUnits,
                    TotalFreeAllocationUnits = fsSizeInfo.AvailableAllocationUnits,
                    BytesPerSector = fsSizeInfo.BytesPerSector,
                    SectorsPerAllocationUnit = fsSizeInfo.SectorsPerAllocationUnit
                };
                return result;
            }
            if (fsInfo is FileFsDeviceInformation)
            {
                FileFsDeviceInformation fsDeviceInfo = (FileFsDeviceInformation)fsInfo;
                QueryFSDeviceInfo result = new QueryFSDeviceInfo
                {
                    DeviceType = fsDeviceInfo.DeviceType,
                    DeviceCharacteristics = fsDeviceInfo.Characteristics
                };
                return result;
            }
            if (fsInfo is FileFsAttributeInformation)
            {
                FileFsAttributeInformation fsAttributeInfo = (FileFsAttributeInformation)fsInfo;
                QueryFSAttibuteInfo result = new QueryFSAttibuteInfo
                {
                    FileSystemAttributes = fsAttributeInfo.FileSystemAttributes,
                    MaxFileNameLengthInBytes = fsAttributeInfo.MaximumComponentNameLength,
                    FileSystemName = fsAttributeInfo.FileSystemName
                };
                return result;
            }
            throw new NotImplementedException();
        }
    }
}