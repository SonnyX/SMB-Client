using System;
using System.Collections.Generic;
using System.Text;

namespace SMBLibrary.Client
{
    class Smb1Handle : NtHandle
    {
        public Smb1Handle(ushort fID)
        {
            FID = fID;
        }

        public ushort FID { get; }
    }
}