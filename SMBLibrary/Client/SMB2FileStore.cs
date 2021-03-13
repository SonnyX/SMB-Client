/* Copyright (C) 2017-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using SMBLibrary.SMB2;

namespace SMBLibrary.Client
{
    public class Smb2FileStore : ISmbFileStore
    {
        private const int BytesPerCredit = 65536;

        private readonly SMB2Client m_client;
        private readonly uint m_treeID;
        private readonly bool m_encryptShareData;

        public Smb2FileStore(SMB2Client client, uint treeID, bool encryptShareData)
        {
            m_client = client;
            m_treeID = treeID;
            m_encryptShareData = encryptShareData;
        }

        public NTStatus CreateFile(out NtHandle? handle, out FileStatus fileStatus, string path,
            AccessMask desiredAccess, FileAttributes fileAttributes, ShareAccess shareAccess,
            CreateDisposition createDisposition, CreateOptions createOptions, SecurityContext? securityContext)
        {
            handle = null;
            fileStatus = FileStatus.FILE_DOES_NOT_EXIST;
            CreateRequest request = new CreateRequest
            {
                Name = path,
                DesiredAccess = desiredAccess,
                FileAttributes = fileAttributes,
                ShareAccess = shareAccess,
                CreateDisposition = createDisposition,
                CreateOptions = createOptions,
                ImpersonationLevel = ImpersonationLevel.Impersonation
            };
            TrySendCommand(request);

            SMB2Command? response = WaitForCommand(SMB2CommandName.Create);
            if (response == null)
                return NTStatus.STATUS_INVALID_SMB;

            if (response.Header.Status != NTStatus.STATUS_SUCCESS || !(response is CreateResponse createResponse))
                return response.Header.Status;

            handle = createResponse.FileId;
            fileStatus = ToFileStatus(createResponse.CreateAction);
            return response.Header.Status;

        }

        public NTStatus CloseFile(NtHandle? handle)
        {
            if (handle == null)
                return NTStatus.STATUS_INVALID_SMB;

            CloseRequest request = new CloseRequest
            {
                FileId = (FileID) handle
            };
            TrySendCommand(request);
            SMB2Command? response = WaitForCommand(SMB2CommandName.Close);
            return response?.Header.Status ?? NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus ReadFile(out byte[]? data, NtHandle? handle, long offset, int maxCount)
        {
            data = null;
            if (handle == null)
                return NTStatus.STATUS_INVALID_SMB;
            ReadRequest request = new ReadRequest
            {
                Header = {CreditCharge = (ushort) Math.Ceiling((double) maxCount / BytesPerCredit)},
                FileId = (FileID) handle,
                Offset = (ulong) offset,
                ReadLength = (uint) maxCount
            };

            TrySendCommand(request);
            SMB2Command? response = WaitForCommand(SMB2CommandName.Read);
            if (response == null)
                return NTStatus.STATUS_INVALID_SMB;

            if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is ReadResponse readResponse)
            {
                data = readResponse.Data;
            }
            return response.Header.Status;
        }

        public NTStatus WriteFile(out int numberOfBytesWritten, NtHandle? handle, long offset, byte[] data)
        {
            numberOfBytesWritten = 0;
            if (handle == null)
                return NTStatus.STATUS_INVALID_SMB;

            WriteRequest request = new WriteRequest
            {
                Header = {CreditCharge = (ushort) Math.Ceiling((double) data.Length / BytesPerCredit)},
                FileId = (FileID) handle,
                Offset = (ulong) offset,
                Data = data
            };

            TrySendCommand(request);
            SMB2Command? response = WaitForCommand(SMB2CommandName.Write);
            if (response == null)
                return NTStatus.STATUS_INVALID_SMB;

            if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is WriteResponse writeResponse)
            {
                numberOfBytesWritten = (int)writeResponse.Count;
            }
            return response.Header.Status;
        }

        public NTStatus FlushFileBuffers(NtHandle? handle)
        {
            throw new NotImplementedException();
        }

        public NTStatus LockFile(NtHandle? handle, long byteOffset, long length, bool exclusiveLock)
        {
            throw new NotImplementedException();
        }

        public NTStatus UnlockFile(NtHandle? handle, long byteOffset, long length)
        {
            throw new NotImplementedException();
        }

        public NTStatus QueryDirectory(out List<QueryDirectoryFileInformation> result, NtHandle? handle, string fileName, FileInformationClass informationClass)
        {
            result = new List<QueryDirectoryFileInformation>();
            if (handle == null)
                return NTStatus.STATUS_INVALID_SMB;

            QueryDirectoryRequest request = new QueryDirectoryRequest
            {
                Header = {CreditCharge = (ushort) Math.Ceiling((double) m_client.MaxTransactSize / BytesPerCredit)},
                FileInformationClass = informationClass,
                Reopen = true,
                FileId = (FileID) handle,
                OutputBufferLength = m_client.MaxTransactSize,
                FileName = fileName
            };

            TrySendCommand(request);
            SMB2Command? response = WaitForCommand(SMB2CommandName.QueryDirectory);
            if (response == null)
                return NTStatus.STATUS_INVALID_SMB;

            while (response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryDirectoryResponse queryDirectoryResponse)
            {
                List<QueryDirectoryFileInformation> page = queryDirectoryResponse.GetFileInformationList(informationClass);
                result.AddRange(page);
                request.Reopen = false;
                TrySendCommand(request);
                response = WaitForCommand(SMB2CommandName.QueryDirectory);
                if (response == null)
                    return NTStatus.STATUS_INVALID_SMB;
            }
            return response.Header.Status;
        }

        public NTStatus GetFileInformation(out FileInformation? result, NtHandle? handle, FileInformationClass informationClass)
        {
            result = null;
            if (handle == null)
                return NTStatus.STATUS_INVALID_SMB;
            QueryInfoRequest request = new QueryInfoRequest
            {
                InfoType = InfoType.File,
                FileInformationClass = informationClass,
                OutputBufferLength = 4096,
                FileId = (FileID)handle
            };

            TrySendCommand(request);
            SMB2Command? response = WaitForCommand(SMB2CommandName.QueryInfo);
            if (response == null)
                return NTStatus.STATUS_INVALID_SMB;

            if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryInfoResponse queryInfoResponse)
            {
                result = queryInfoResponse.GetFileInformation(informationClass);
            }
            return response.Header.Status;
        }

        public NTStatus SetFileInformation(NtHandle? handle, FileInformation information)
        {
            if (handle == null)
                return NTStatus.STATUS_INVALID_SMB;
            SetInfoRequest request = new SetInfoRequest
            {
                InfoType = InfoType.File,
                FileInformationClass = information.FileInformationClass,
                FileId = (FileID)handle
            };
            request.SetFileInformation(information);

            TrySendCommand(request);
            SMB2Command? response = WaitForCommand(SMB2CommandName.SetInfo);
            return response?.Header.Status ?? NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus GetFileSystemInformation(out FileSystemInformation? result, FileSystemInformationClass informationClass)
        {
            result = null;

            NTStatus status = CreateFile(out NtHandle? fileHandle, out _, string.Empty, (AccessMask)DirectoryAccessMask.FILE_LIST_DIRECTORY | (AccessMask)DirectoryAccessMask.FILE_READ_ATTRIBUTES | AccessMask.SYNCHRONIZE, 0, ShareAccess.Read | ShareAccess.Write | ShareAccess.Delete, CreateDisposition.FILE_OPEN, CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT | CreateOptions.FILE_DIRECTORY_FILE, null);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return status;
            }

            status = GetFileSystemInformation(out result, fileHandle, informationClass);
            CloseFile(fileHandle);
            return status;
        }

        public NTStatus GetFileSystemInformation(out FileSystemInformation? result, NtHandle? handle, FileSystemInformationClass informationClass)
        {
            result = null;
            if (handle == null)
                return NTStatus.STATUS_INVALID_SMB;
            QueryInfoRequest request = new QueryInfoRequest
            {
                InfoType = InfoType.FileSystem,
                FileSystemInformationClass = informationClass,
                OutputBufferLength = 4096,
                FileId = (FileID) handle
            };

            TrySendCommand(request);
            SMB2Command? response = WaitForCommand(SMB2CommandName.QueryInfo);
            if (response == null)
                return NTStatus.STATUS_INVALID_SMB;

            if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryInfoResponse queryInfoResponse)
            {
                result = queryInfoResponse.GetFileSystemInformation(informationClass);
            }
            return response.Header.Status;
        }

        public NTStatus SetFileSystemInformation(FileSystemInformation information)
        {
            throw new NotImplementedException();
        }

        public NTStatus GetSecurityInformation(out SecurityDescriptor result, NtHandle? handle, SecurityInformation securityInformation)
        {
            result = null;
            if (handle == null)
                return NTStatus.STATUS_INVALID_SMB;
            QueryInfoRequest request = new QueryInfoRequest
            {
                InfoType = InfoType.Security,
                SecurityInformation = securityInformation,
                OutputBufferLength = 4096,
                FileId = (FileID) handle
            };

            TrySendCommand(request);
            SMB2Command? response = WaitForCommand(SMB2CommandName.QueryInfo);
            if (response == null)
                return NTStatus.STATUS_INVALID_SMB;
            if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryInfoResponse queryInfoResponse)
            {
                result = queryInfoResponse.GetSecurityInformation();
            }
            return response.Header.Status;

        }

        public NTStatus SetSecurityInformation(NtHandle? handle, SecurityInformation securityInformation, SecurityDescriptor securityDescriptor)
        {
            return NTStatus.STATUS_NOT_SUPPORTED;
        }

        public NTStatus NotifyChange(out object ioRequest, NtHandle? handle, NotifyChangeFilter completionFilter, bool watchTree, int outputBufferSize, OnNotifyChangeCompleted onNotifyChangeCompleted, object context)
        {
            throw new NotImplementedException();
        }

        public NTStatus Cancel(object ioRequest)
        {
            throw new NotImplementedException();
        }

        public NTStatus DeviceIOControl(NtHandle? handle, uint ctlCode, byte[] input, out byte[] output, int maxOutputLength)
        {
            output = null;
            if (handle == null)
                return NTStatus.STATUS_INVALID_SMB;
            IOCtlRequest request = new IOCtlRequest
            {
                Header = {CreditCharge = (ushort) Math.Ceiling((double) maxOutputLength / BytesPerCredit)},
                CtlCode = ctlCode,
                IsFSCtl = true,
                FileId = (FileID) handle,
                Input = input,
                MaxOutputResponse = (uint) maxOutputLength
            };
            TrySendCommand(request);
            SMB2Command? response = WaitForCommand(SMB2CommandName.IOCtl);
            if (response == null)
                return NTStatus.STATUS_INVALID_SMB;

            if ((response.Header.Status == NTStatus.STATUS_SUCCESS || response.Header.Status == NTStatus.STATUS_BUFFER_OVERFLOW) && response is IOCtlResponse ioCtlResponse)
            {
                output = ioCtlResponse.Output;
            }
            return response.Header.Status;

        }

        public NTStatus Disconnect()
        {
            TreeDisconnectRequest request = new TreeDisconnectRequest();
            TrySendCommand(request);
            SMB2Command? response = WaitForCommand(SMB2CommandName.TreeDisconnect);
            return response?.Header.Status ?? NTStatus.STATUS_INVALID_SMB;
        }

        private SMB2Command? WaitForCommand(SMB2CommandName commandName)
        {
            return m_client.WaitForCommand(commandName);
        }

        private void TrySendCommand(SMB2Command request)
        {
            request.Header.TreeID = m_treeID;
            m_client.TrySendCommand(request, m_encryptShareData);
        }

        public uint MaxReadSize => m_client.MaxReadSize;

        public uint MaxWriteSize => m_client.MaxWriteSize;

        private static FileStatus ToFileStatus(CreateAction createAction)
        {
            return createAction switch
            {
                CreateAction.FILE_SUPERSEDED => FileStatus.FILE_SUPERSEDED,
                CreateAction.FILE_OPENED => FileStatus.FILE_OPENED,
                CreateAction.FILE_CREATED => FileStatus.FILE_CREATED,
                CreateAction.FILE_OVERWRITTEN => FileStatus.FILE_OVERWRITTEN,
                _ => FileStatus.FILE_OPENED
            };
        }
    }
}