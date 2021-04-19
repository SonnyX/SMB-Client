/* Copyright (C) 2017-2021 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
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

        private readonly Smb2Client m_client;
        private readonly uint m_treeID;
        private readonly bool m_encryptShareData;

        public Smb2FileStore(Smb2Client client, uint treeID, bool encryptShareData)
        {
            m_client = client;
            m_treeID = treeID;
            m_encryptShareData = encryptShareData;
        }

        public void CreateFile(out NtHandle handle, out FileStatus fileStatus, string path,
            AccessMask desiredAccess, FileAttributes fileAttributes, ShareAccess shareAccess,
            CreateDisposition createDisposition, CreateOptions createOptions, SecurityContext? securityContext)
        {
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
            SendCommand(request);

            CreateResponse createResponse = (CreateResponse) WaitForCommand(request.MessageID);
            createResponse.IsSuccessElseThrow();

            handle = createResponse.FileId;
            fileStatus = ToFileStatus(createResponse.CreateAction);
        }

        public void CloseFile(NtHandle handle)
        {
            CloseRequest request = new CloseRequest
            {
                FileId = (FileID)handle
            };
            SendCommand(request);
            SMB2Command? response = WaitForCommand(request.MessageID);
            if(response.Header.Status != NTStatus.STATUS_FILE_CLOSED)
                response?.IsSuccessElseThrow();
        }

        public void ReadFile(out byte[] data, NtHandle handle, long offset, int maxCount)
        {
            ReadRequest request = new ReadRequest
            {
                Header = { CreditCharge = (ushort)Math.Ceiling((double)maxCount / BytesPerCredit) },
                FileId = (FileID)handle,
                Offset = (ulong)offset,
                ReadLength = (uint)maxCount
            };

            SendCommand(request);
            ReadResponse readResponse = (ReadResponse) WaitForCommand(request.MessageID);
            readResponse.IsSuccessElseThrow();
            data = readResponse.Data;
        }

        public void WriteFile(out int numberOfBytesWritten, NtHandle handle, long offset, byte[] data)
        {
            WriteRequest request = new WriteRequest
            {
                Header = { CreditCharge = (ushort)Math.Ceiling((double)data.Length / BytesPerCredit) },
                FileId = (FileID)handle,
                Offset = (ulong)offset,
                Data = data
            };

            SendCommand(request);
            WriteResponse writeResponse = (WriteResponse) WaitForCommand(request.MessageID);
            writeResponse.IsSuccessElseThrow();
            numberOfBytesWritten = (int)writeResponse.Count;
        }

        public void FlushFileBuffers(NtHandle handle)
        {
            throw new NotImplementedException();
        }

        public void LockFile(NtHandle handle, long byteOffset, long length, bool exclusiveLock)
        {
            throw new NotImplementedException();
        }

        public void UnlockFile(NtHandle handle, long byteOffset, long length)
        {
            throw new NotImplementedException();
        }

        public void QueryDirectory(out List<QueryDirectoryFileInformation> result, NtHandle handle, string fileName, FileInformationClass informationClass)
        {
            result = new List<QueryDirectoryFileInformation>();

            QueryDirectoryRequest request = new QueryDirectoryRequest
            {
                Header = { CreditCharge = (ushort)Math.Ceiling((double)m_client.MaxTransactSize / BytesPerCredit) },
                FileInformationClass = informationClass,
                Reopen = true,
                FileId = (FileID)handle,
                OutputBufferLength = m_client.MaxTransactSize,
                FileName = fileName
            };

            SendCommand(request);
            SMB2Command? response = WaitForCommand(request.MessageID);
            response.IsSuccessElseThrow();

            while (response is QueryDirectoryResponse queryDirectoryResponse)
            {
                List<QueryDirectoryFileInformation> page = queryDirectoryResponse.GetFileInformationList(informationClass);
                result.AddRange(page);
                request.Reopen = false;
                SendCommand(request);
                response = WaitForCommand(request.MessageID);
                if (response.Header.Status == NTStatus.STATUS_NO_MORE_FILES)
                    break;

                response.IsSuccessElseThrow();
            }
        }

        public void GetFileInformation(out FileInformation result, NtHandle handle, FileInformationClass informationClass)
        {
            QueryInfoRequest request = new QueryInfoRequest
            {
                InfoType = InfoType.File,
                FileInformationClass = informationClass,
                OutputBufferLength = 4096,
                FileId = (FileID)handle
            };

            SendCommand(request);
            QueryInfoResponse queryInfoResponse = (QueryInfoResponse) WaitForCommand(request.MessageID);
            queryInfoResponse.IsSuccessElseThrow();
            result = queryInfoResponse.GetFileInformation(informationClass);
        }

        public void SetFileInformation(NtHandle handle, FileInformation information)
        {
            SetInfoRequest request = new SetInfoRequest
            {
                InfoType = InfoType.File,
                FileInformationClass = information.FileInformationClass,
                FileId = (FileID)handle
            };
            request.SetFileInformation(information);

            SendCommand(request);
            SMB2Command response = WaitForCommand(request.MessageID);
            response.IsSuccessElseThrow();
        }

        public void GetFileSystemInformation(out FileSystemInformation result, FileSystemInformationClass informationClass)
        {
            CreateFile(out NtHandle fileHandle, out _, string.Empty, (AccessMask)DirectoryAccessMask.FILE_LIST_DIRECTORY | (AccessMask)DirectoryAccessMask.FILE_READ_ATTRIBUTES | AccessMask.SYNCHRONIZE, 0, ShareAccess.Read | ShareAccess.Write | ShareAccess.Delete, CreateDisposition.FILE_OPEN, CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT | CreateOptions.FILE_DIRECTORY_FILE, null);
            GetFileSystemInformation(out result, fileHandle, informationClass);
            CloseFile(fileHandle);
        }

        public void GetFileSystemInformation(out FileSystemInformation result, NtHandle handle, FileSystemInformationClass informationClass)
        {
            QueryInfoRequest request = new QueryInfoRequest
            {
                InfoType = InfoType.FileSystem,
                FileSystemInformationClass = informationClass,
                OutputBufferLength = 4096,
                FileId = (FileID)handle
            };

            SendCommand(request);
            QueryInfoResponse queryInfoResponse = (QueryInfoResponse) WaitForCommand(request.MessageID);
            queryInfoResponse.IsSuccessElseThrow();
            result = queryInfoResponse.GetFileSystemInformation(informationClass);
        }

        public void SetFileSystemInformation(FileSystemInformation information)
        {
            throw new NotImplementedException();
        }

        public void GetSecurityInformation(out SecurityDescriptor? result, NtHandle handle, SecurityInformation securityInformation)
        {
            result = null;

            QueryInfoRequest request = new QueryInfoRequest
            {
                InfoType = InfoType.Security,
                SecurityInformation = securityInformation,
                OutputBufferLength = 4096,
                FileId = (FileID)handle
            };

            SendCommand(request);
            SMB2Command response = WaitForCommand(request.MessageID);
            response.IsSuccessElseThrow();

            if (response is QueryInfoResponse queryInfoResponse)
            {
                result = queryInfoResponse.GetSecurityInformation();
            }
        }

        public void SetSecurityInformation(NtHandle handle, SecurityInformation securityInformation, SecurityDescriptor securityDescriptor)
        {
            throw new NtStatusException(NTStatus.STATUS_NOT_SUPPORTED);
        }

        public void NotifyChange(out object ioRequest, NtHandle handle, NotifyChangeFilter completionFilter, bool watchTree, int outputBufferSize, OnNotifyChangeCompleted onNotifyChangeCompleted, object context)
        {
            throw new NotImplementedException();
        }

        public void Cancel(object ioRequest)
        {
            throw new NotImplementedException();
        }

        public void DeviceIOControl(NtHandle handle, uint ctlCode, byte[] input, out byte[]? output, int maxOutputLength)
        {
            output = null;

            IOCtlRequest request = new IOCtlRequest
            {
                Header = { CreditCharge = (ushort)Math.Ceiling((double)maxOutputLength / BytesPerCredit) },
                CtlCode = ctlCode,
                IsFSCtl = true,
                FileId = (FileID)handle,
                Input = input,
                MaxOutputResponse = (uint)maxOutputLength
            };
            SendCommand(request);
            SMB2Command response = WaitForCommand(request.MessageID);
            response.IsSuccessOrBufferOverflowElseThrow();
            if (response is IOCtlResponse ioCtlResponse)
            {
                output = ioCtlResponse.Output;
            }
        }

        public void Disconnect()
        {
            TreeDisconnectRequest request = new TreeDisconnectRequest();
            SendCommand(request);
            SMB2Command response = WaitForCommand(request.MessageID);
            response.IsSuccessElseThrow();
        }

        private SMB2Command WaitForCommand(ulong messageID)
        {
            return m_client.WaitForCommand(messageID);
        }

        private void SendCommand(SMB2Command request)
        {
            request.Header.TreeID = m_treeID;
            m_client.SendCommand(request, m_encryptShareData);
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