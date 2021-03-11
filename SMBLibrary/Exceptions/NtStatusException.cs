using System;

namespace SMBLibrary.Client
{
    public class NtStatusException : Exception
    {
        private NTStatus status;

        public NtStatusException(NTStatus status)
        {
            this.status = status;
            Message = $"NtStatus returned with status: {status}";
        }

        public override string Message { get; }
    }
}