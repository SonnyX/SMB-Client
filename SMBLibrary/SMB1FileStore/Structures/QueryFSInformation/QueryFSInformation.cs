/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary.SMB1
{
    public abstract class QueryFSInformation
    {
        public abstract byte[] GetBytes(bool isUnicode);

        public abstract int Length
        {
            get;
        }

        public abstract QueryFSInformationLevel InformationLevel
        {
            get;
        }

        public static QueryFSInformation GetQueryFSInformation(byte[] buffer, QueryFSInformationLevel informationLevel)
        {
            return informationLevel switch
            {
                QueryFSInformationLevel.SMB_QUERY_FS_VOLUME_INFO => new QueryFSVolumeInfo(buffer, 0),
                QueryFSInformationLevel.SMB_QUERY_FS_SIZE_INFO => new QueryFSSizeInfo(buffer),
                QueryFSInformationLevel.SMB_QUERY_FS_DEVICE_INFO => new QueryFSDeviceInfo(buffer, 0),
                QueryFSInformationLevel.SMB_QUERY_FS_ATTRIBUTE_INFO => new QueryFSAttibuteInfo(buffer, 0),
                _ => throw new UnsupportedInformationLevelException()
            };
        }
    }
}