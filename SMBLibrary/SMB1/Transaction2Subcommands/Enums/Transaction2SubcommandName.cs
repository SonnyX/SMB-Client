namespace SMBLibrary.SMB1
{
    public enum Transaction2SubcommandName : ushort
    {
        TRANS2_OPEN2 = 0x0000,
        TRANS2_FIND_FIRST2 = 0x0001,
        TRANS2_FIND_NEXT2 = 0x0002,
        TRANS2_QUERY_FS_INFORMATION = 0x0003,
        TRANS2_SET_FS_INFORMATION = 0x0004,
        TRANS2_QUERY_PATH_INFORMATION = 0x0005,
        TRANS2_SET_PATH_INFORMATION = 0x006,
        TRANS2_QUERY_FILE_INFORMATION = 0x0007,
        TRANS2_SET_FILE_INFORMATION = 0x0008,
        TRANS2_CREATE_DIRECTORY = 0x000D,
        TRANS2_GET_DFS_REFERRAL = 0x0010,
    }
}