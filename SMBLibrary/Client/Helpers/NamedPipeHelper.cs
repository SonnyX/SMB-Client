/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using SMBLibrary.RPC;
using SMBLibrary.Services;

namespace SMBLibrary.Client
{
    public class NamedPipeHelper
    {
        public static NTStatus BindPipe(INTFileStore namedPipeShare, string pipeName, Guid interfaceGuid, uint interfaceVersion, out object pipeHandle, out int maxTransmitFragmentSize)
        {
            maxTransmitFragmentSize = 0;
            NTStatus status = namedPipeShare.CreateFile(out pipeHandle, out _, pipeName, (AccessMask)(FileAccessMask.FILE_READ_DATA | FileAccessMask.FILE_WRITE_DATA), 0, ShareAccess.Read | ShareAccess.Write, CreateDisposition.FILE_OPEN, 0, null);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return status;
            }
            BindPDU bindPDU = new BindPDU
            {
                Flags = PacketFlags.FirstFragment | PacketFlags.LastFragment
            };
            bindPDU.DataRepresentation.CharacterFormat = CharacterFormat.ASCII;
            bindPDU.DataRepresentation.ByteOrder = ByteOrder.LittleEndian;
            bindPDU.DataRepresentation.FloatingPointRepresentation = FloatingPointRepresentation.IEEE;
            bindPDU.MaxTransmitFragmentSize = 5680;
            bindPDU.MaxReceiveFragmentSize = 5680;

            ContextElement serviceContext = new ContextElement
            {
                AbstractSyntax = new SyntaxID(interfaceGuid, interfaceVersion)
            };
            serviceContext.TransferSyntaxList.Add(new SyntaxID(RemoteServiceHelper.NDRTransferSyntaxIdentifier, RemoteServiceHelper.NDRTransferSyntaxVersion));

            bindPDU.ContextList.Add(serviceContext);

            byte[] input = bindPDU.GetBytes();
            status = namedPipeShare.DeviceIOControl(pipeHandle, (uint)IoControlCode.FSCTL_PIPE_TRANSCEIVE, input, out byte[] output, 4096);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return status;
            }

            if (!(RPCPDU.GetPDU(output, 0) is BindAckPDU bindAckPDU))
                return NTStatus.STATUS_NOT_SUPPORTED;

            maxTransmitFragmentSize = bindAckPDU.MaxTransmitFragmentSize;
            return NTStatus.STATUS_SUCCESS;
        }
    }
}