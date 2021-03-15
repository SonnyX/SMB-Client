using SMBLibrary.Client;
using SMBLibrary.SMB1;
using SMBLibrary.SMB2;

namespace SMBLibrary
{
    public static class OrThrowHelper
    {
        public static void IsSuccessElseThrow(this NTStatus ntStatus)
        {
            if (ntStatus != NTStatus.STATUS_SUCCESS && ntStatus != NTStatus.STATUS_END_OF_FILE)
                throw new NtStatusException(ntStatus);
        }

        public static void IsSuccessElseThrow(this SMB2Command smbCommand)
        {
            if (smbCommand.Header.Status != NTStatus.STATUS_SUCCESS && smbCommand.Header.Status != NTStatus.STATUS_END_OF_FILE)
                throw new NtStatusException(smbCommand.Header.Status);
        }

        public static void MoreProcessingRequiredElseThrow(this SMB2Command smbCommand)
        {
            if (smbCommand.Header.Status != NTStatus.STATUS_MORE_PROCESSING_REQUIRED)
                throw new NtStatusException(smbCommand.Header.Status);
        }

        public static void IsSuccessElseThrow(this SMB1Message smbCommand)
        {
            if (smbCommand.Header.Status != NTStatus.STATUS_SUCCESS && smbCommand.Header.Status != NTStatus.STATUS_END_OF_FILE)
                throw new NtStatusException(smbCommand.Header.Status);
        }

        public static void IsSuccessOrBufferOverflowElseThrow(this SMB2Command smbCommand)
        {
            if (smbCommand.Header.Status != NTStatus.STATUS_SUCCESS && smbCommand.Header.Status != NTStatus.STATUS_BUFFER_OVERFLOW)
                throw new NtStatusException(smbCommand.Header.Status);
        }
    }
}