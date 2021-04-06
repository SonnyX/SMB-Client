/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.IO;

namespace SMBLibrary.SMB1
{
    public abstract class NTTransactSubcommand
    {
        public NTTransactSubcommand()
        {
        }

        public virtual byte[] GetSetup()
        {
            return new byte[0];
        }

        public virtual byte[] GetParameters(bool isUnicode)
        {
            return new byte[0];
        }

        public virtual byte[] GetData()
        {
            return new byte[0];
        }

        public abstract NTTransactSubcommandName SubcommandName { get; }

        public static NTTransactSubcommand GetSubcommandRequest(NTTransactSubcommandName subcommandName, byte[] setup, byte[] parameters, byte[] data, bool isUnicode)
        {
            return subcommandName switch
            {
                NTTransactSubcommandName.NT_TRANSACT_CREATE => new NTTransactCreateRequest(parameters, data, isUnicode),
                NTTransactSubcommandName.NT_TRANSACT_IOCTL => new NTTransactIOCTLRequest(setup, data),
                NTTransactSubcommandName.NT_TRANSACT_SET_SECURITY_DESC => new NTTransactSetSecurityDescriptorRequest(parameters, data),
                NTTransactSubcommandName.NT_TRANSACT_NOTIFY_CHANGE => new NTTransactNotifyChangeRequest(setup),
                NTTransactSubcommandName.NT_TRANSACT_QUERY_SECURITY_DESC => new NTTransactQuerySecurityDescriptorRequest(parameters),
                _ => throw new InvalidDataException()
            };
        }
    }
}