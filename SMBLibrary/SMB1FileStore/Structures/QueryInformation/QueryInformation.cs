/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary.SMB1
{
    public abstract class QueryInformation
    {
        public abstract byte[] GetBytes();

        public abstract QueryInformationLevel InformationLevel
        {
            get;
        }

        public static QueryInformation GetQueryInformation(byte[] buffer, QueryInformationLevel informationLevel)
        {
            return informationLevel switch
            {
                QueryInformationLevel.SMB_QUERY_FILE_BASIC_INFO => new QueryFileBasicInfo(buffer, 0),
                QueryInformationLevel.SMB_QUERY_FILE_STANDARD_INFO => new QueryFileStandardInfo(buffer, 0),
                QueryInformationLevel.SMB_QUERY_FILE_EA_INFO => new QueryFileEaInfo(buffer, 0),
                QueryInformationLevel.SMB_QUERY_FILE_NAME_INFO => new QueryFileNameInfo(buffer),
                QueryInformationLevel.SMB_QUERY_FILE_ALL_INFO => new QueryFileAllInfo(buffer, 0),
                QueryInformationLevel.SMB_QUERY_FILE_ALT_NAME_INFO => new QueryFileAltNameInfo(buffer, 0),
                QueryInformationLevel.SMB_QUERY_FILE_STREAM_INFO => new QueryFileStreamInfo(buffer, 0),
                QueryInformationLevel.SMB_QUERY_FILE_COMPRESSION_INFO => new QueryFileCompressionInfo(buffer, 0),
                _ => throw new UnsupportedInformationLevelException()
            };
        }
    }
}