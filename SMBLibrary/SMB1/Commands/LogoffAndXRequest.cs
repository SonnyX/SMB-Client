/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_COM_LOGOFF_ANDX Request
    /// </summary>
    public class LogoffAndXRequest : SMBAndXCommand
    {
        public const int ParametersLength = 4;

        public LogoffAndXRequest()
        {
        }

        public LogoffAndXRequest(byte[] buffer, int offset) : base(buffer, offset)
        {
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            SMBParameters = new byte[ParametersLength];
            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_LOGOFF_ANDX;
    }
}