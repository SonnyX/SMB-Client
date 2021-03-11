/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;
using SMBLibrary.SMB1;

namespace SMBLibrary.Server.SMB1
{
    internal class EchoHelper
    {
        internal static List<SMB1Command> GetEchoResponse(EchoRequest request)
        {
            List<SMB1Command> response = new List<SMB1Command>();
            for (int index = 0; index < request.EchoCount; index++)
            {
                EchoResponse echo = new EchoResponse
                {
                    SequenceNumber = (ushort)index,
                    Data = request.Data
                };
                response.Add(echo);
            }
            return response;
        }

        internal static SMB1Message GetUnsolicitedEchoReply()
        {
            // [MS-CIFS] 3.2.5.1 - If the PID and MID values of the received message are not found in the
            // Client.Connection.PIDMIDList, the message MUST be discarded.
            SMB1Header header = new SMB1Header
            {
                Command = CommandName.SMB_COM_ECHO,
                Status = NTStatus.STATUS_SUCCESS,
                Flags = HeaderFlags.CaseInsensitive | HeaderFlags.CanonicalizedPaths | HeaderFlags.Reply,
                // [MS-CIFS] SMB_FLAGS2_LONG_NAMES SHOULD be set to 1 when the negotiated dialect is NT LANMAN.
                // [MS-CIFS] SMB_FLAGS2_UNICODE SHOULD be set to 1 when the negotiated dialect is NT LANMAN.
                Flags2 = HeaderFlags2.LongNamesAllowed | HeaderFlags2.NTStatusCode | HeaderFlags2.Unicode,
                UID = 0xFFFF,
                TID = 0xFFFF,
                PID = 0xFFFFFFFF,
                MID = 0xFFFF
            };

            EchoResponse response = new EchoResponse();
            SMB1Message reply = new SMB1Message
            {
                Header = header
            };
            reply.Commands.Add(response);
            return reply;
        }
    }
}
