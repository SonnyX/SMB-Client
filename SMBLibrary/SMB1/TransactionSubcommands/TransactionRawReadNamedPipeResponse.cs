/* Copyright (C) 2014-2019 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// TRANS_RAW_READ_NMPIPE Response
    /// </summary>
    public class TransactionRawReadNamedPipeResponse : TransactionSubcommand
    {
        public const int ParametersLength = 0;
        // Data:
        public byte[]? BytesRead;

        public TransactionRawReadNamedPipeResponse()
        {
        }

        public TransactionRawReadNamedPipeResponse(byte[] data)
        {
            BytesRead = data;
        }

        public override byte[] GetData(bool isUnicode)
        {
            return BytesRead ?? new byte[0];
        }

        public override TransactionSubcommandName SubcommandName => TransactionSubcommandName.TRANS_RAW_READ_NMPIPE;
    }
}
