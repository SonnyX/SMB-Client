/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;
using System.Linq;
using SMBLibrary.RPC;
using SMBLibrary.Services;
using Utilities;

namespace SMBLibrary.Client
{
    public class ServerServiceHelper
    {
        public static List<string>? ListShares(INtFileStore namedPipeShare, ShareType? shareType, out NTStatus status)
        {
            status = NamedPipeHelper.BindPipe(namedPipeShare, ServerService.ServicePipeName, ServerService.ServiceInterfaceGuid, ServerService.ServiceVersion, out NtHandle? pipeHandle, out int maxTransmitFragmentSize);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return null;
            }

            NetrShareEnumRequest shareEnumRequest = new NetrShareEnumRequest
            {
                InfoStruct = new ShareEnum
                {
                    Level = 1,
                    Info = new ShareInfo1Container()
                },
                PreferedMaximumLength = uint.MaxValue,
                ServerName = "*"
            };

            byte[] data = shareEnumRequest.GetBytes();
            RequestPDU requestPdu = new RequestPDU
            {
                Flags = PacketFlags.FirstFragment | PacketFlags.LastFragment,
                DataRepresentation =
                {
                    CharacterFormat = CharacterFormat.ASCII,
                    ByteOrder = ByteOrder.LittleEndian,
                    FloatingPointRepresentation = FloatingPointRepresentation.IEEE
                },
                OpNum = (ushort) ServerServiceOpName.NetrShareEnum,
                Data = data,
                AllocationHint = (uint)data.Length
            };
            byte[] input = requestPdu.GetBytes();
            status = namedPipeShare.DeviceIOControl(pipeHandle, (uint)IoControlCode.FSCTL_PIPE_TRANSCEIVE, input, out byte[]? output, maxTransmitFragmentSize);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return null;
            }

            if (!(RPCPDU.GetPDU(output, 0) is ResponsePDU responsePdu))
            {
                status = NTStatus.STATUS_NOT_SUPPORTED;
                return null;
            }

            byte[] responseData = responsePdu.Data;
            while ((responsePdu.Flags & PacketFlags.LastFragment) == 0)
            {
                status = namedPipeShare.ReadFile(out output, pipeHandle, 0, maxTransmitFragmentSize);
                if (status != NTStatus.STATUS_SUCCESS)
                {
                    return null;
                }

                if (!(RPCPDU.GetPDU(output, 0) is ResponsePDU responsePdu2))
                {
                    status = NTStatus.STATUS_NOT_SUPPORTED;
                    return null;
                }
                responseData = ByteUtils.Concatenate(responseData, responsePdu2.Data);
            }
            namedPipeShare.CloseFile(pipeHandle);
            NetrShareEnumResponse shareEnumResponse = new NetrShareEnumResponse(responseData);
            if (shareEnumResponse.InfoStruct.Info is ShareInfo1Container shareInfo1 && shareInfo1.Entries != null)
                return (from entry in shareInfo1.Entries where !shareType.HasValue || shareType.Value == entry.ShareType.ShareType select entry.NetName.Value).ToList();

            status = shareEnumResponse.Result == Win32Error.ERROR_ACCESS_DENIED ? NTStatus.STATUS_ACCESS_DENIED : NTStatus.STATUS_NOT_SUPPORTED;
            return null;

        }
    }
}