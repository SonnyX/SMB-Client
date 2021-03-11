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
    public class SMB2FileStore : ISMBFileStore
    {
        private const int BytesPerCredit = 65536;

        private readonly SMB2Client m_client;
        private readonly uint m_treeID;
        private readonly bool m_encryptShareData;

        public SMB2FileStore(SMB2Client client, uint treeID, bool encryptShareData)
        {
            m_client = client;
            m_treeID = treeID;
            m_encryptShareData = encryptShareData;
        }

        public NTStatus CreateFile(out object handle, out FileStatus fileStatus, string path, AccessMask desiredAccess, FileAttributes fileAttributes, ShareAccess shareAccess, CreateDisposition createDisposition, CreateOptions createOptions, SecurityContext securityContext)
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

            SMB2Command response = WaitForCommand(SMB2CommandName.Create);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is CreateResponse)
                {
                    CreateResponse createResponse = ((CreateResponse)response);
                    handle = createResponse.FileId;
                    fileStatus = ToFileStatus(createResponse.CreateAction);
                }
                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus CloseFile(object handle)
        {
            CloseRequest request = new CloseRequest
            {
                FileId = (FileID)handle
            };
            TrySendCommand(request);
            SMB2Command response = WaitForCommand(SMB2CommandName.Close);
            if (response != null)
            {
                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus ReadFile(out byte[] data, object handle, long offset, int maxCount)
        {
            data = null;
            ReadRequest request = new ReadRequest();
            request.Header.CreditCharge = (ushort)Math.Ceiling((double)maxCount / BytesPerCredit);
            request.FileId = (FileID)handle;
            request.Offset = (ulong)offset;
            request.ReadLength = (uint)maxCount;

            TrySendCommand(request);
            SMB2Command response = WaitForCommand(SMB2CommandName.Read);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is ReadResponse)
                {
                    data = ((ReadResponse)response).Data;
                }
                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus WriteFile(out int numberOfBytesWritten, object handle, long offset, byte[] data)
        {
            numberOfBytesWritten = 0;
            WriteRequest request = new WriteRequest();
            request.Header.CreditCharge = (ushort)Math.Ceiling((double)data.Length / BytesPerCredit);
            request.FileId = (FileID)handle;
            request.Offset = (ulong)offset;
            request.Data = data;

            TrySendCommand(request);
            SMB2Command response = WaitForCommand(SMB2CommandName.Write);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is WriteResponse)
                {
                    numberOfBytesWritten = (int)((WriteResponse)response).Count;
                }
                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus FlushFileBuffers(object handle)
        {
            throw new NotImplementedException();
        }

        public NTStatus LockFile(object handle, long byteOffset, long length, bool exclusiveLock)
        {
            throw new NotImplementedException();
        }

        public NTStatus UnlockFile(object handle, long byteOffset, long length)
        {
            throw new NotImplementedException();
        }

        public NTStatus QueryDirectory(out List<QueryDirectoryFileInformation> result, object handle, string fileName, FileInformationClass informationClass)
        {
            result = new List<QueryDirectoryFileInformation>();
            QueryDirectoryRequest request = new QueryDirectoryRequest();
            request.Header.CreditCharge = (ushort)Math.Ceiling((double)m_client.MaxTransactSize / BytesPerCredit);
            request.FileInformationClass = informationClass;
            request.Reopen = true;
            request.FileId = (FileID)handle;
            request.OutputBufferLength = m_client.MaxTransactSize;
            request.FileName = fileName;

            TrySendCommand(request);
            SMB2Command response = WaitForCommand(SMB2CommandName.QueryDirectory);
            if (response != null)
            {
                while (response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryDirectoryResponse)
                {
                    List<QueryDirectoryFileInformation> page = ((QueryDirectoryResponse)response).GetFileInformationList(informationClass);
                    result.AddRange(page);
                    request.Reopen = false;
                    TrySendCommand(request);
                    response = WaitForCommand(SMB2CommandName.QueryDirectory);
                }
                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus GetFileInformation(out FileInformation result, object handle, FileInformationClass informationClass)
        {
            result = null;
            QueryInfoRequest request = new QueryInfoRequest
            {
                InfoType = InfoType.File,
                FileInformationClass = informationClass,
                OutputBufferLength = 4096,
                FileId = (FileID)handle
            };

            TrySendCommand(request);
            SMB2Command response = WaitForCommand(SMB2CommandName.QueryInfo);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryInfoResponse)
                {
                    result = ((QueryInfoResponse)response).GetFileInformation(informationClass);
                }
                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus SetFileInformation(object handle, FileInformation information)
        {
            SetInfoRequest request = new SetInfoRequest
            {
                InfoType = InfoType.File,
                FileInformationClass = information.FileInformationClass,
                FileId = (FileID)handle
            };
            request.SetFileInformation(information);

            TrySendCommand(request);
            SMB2Command response = WaitForCommand(SMB2CommandName.SetInfo);
            if (response != null)
            {
                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus GetFileSystemInformation(out FileSystemInformation result, FileSystemInformationClass informationClass)
        {
            result = null;
            NTStatus status = CreateFile(out object fileHandle, out _, string.Empty, (AccessMask)DirectoryAccessMask.FILE_LIST_DIRECTORY | (AccessMask)DirectoryAccessMask.FILE_READ_ATTRIBUTES | AccessMask.SYNCHRONIZE, 0, ShareAccess.Read | ShareAccess.Write | ShareAccess.Delete, CreateDisposition.FILE_OPEN, CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT | CreateOptions.FILE_DIRECTORY_FILE, null);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return status;
            }

            status = GetFileSystemInformation(out result, fileHandle, informationClass);
            CloseFile(fileHandle);
            return status;
        }

        public NTStatus GetFileSystemInformation(out FileSystemInformation result, object handle, FileSystemInformationClass informationClass)
        {
            result = null;
            QueryInfoRequest request = new QueryInfoRequest
            {
                InfoType = InfoType.FileSystem,
                FileSystemInformationClass = informationClass,
                OutputBufferLength = 4096,
                FileId = (FileID)handle
            };

            TrySendCommand(request);
            SMB2Command response = WaitForCommand(SMB2CommandName.QueryInfo);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryInfoResponse)
                {
                    result = ((QueryInfoResponse)response).GetFileSystemInformation(informationClass);
                }
                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus SetFileSystemInformation(FileSystemInformation information)
        {
            throw new NotImplementedException();
        }

        public NTStatus GetSecurityInformation(out SecurityDescriptor result, object handle, SecurityInformation securityInformation)
        {
            result = null;
            QueryInfoRequest request = new QueryInfoRequest
            {
                InfoType = InfoType.Security,
                SecurityInformation = securityInformation,
                OutputBufferLength = 4096,
                FileId = (FileID)handle
            };

            TrySendCommand(request);
            SMB2Command response = WaitForCommand(SMB2CommandName.QueryInfo);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryInfoResponse)
                {
                    result = ((QueryInfoResponse)response).GetSecurityInformation();
                }
                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus SetSecurityInformation(object handle, SecurityInformation securityInformation, SecurityDescriptor securityDescriptor)
        {
            return NTStatus.STATUS_NOT_SUPPORTED;
        }

        public NTStatus NotifyChange(out object ioRequest, object handle, NotifyChangeFilter completionFilter, bool watchTree, int outputBufferSize, OnNotifyChangeCompleted onNotifyChangeCompleted, object context)
        {
            throw new NotImplementedException();
        }

        public NTStatus Cancel(object ioRequest)
        {
            throw new NotImplementedException();
        }

        public NTStatus DeviceIOControl(object handle, uint ctlCode, byte[] input, out byte[] output, int maxOutputLength)
        {
            output = null;
            IOCtlRequest request = new IOCtlRequest();
            request.Header.CreditCharge = (ushort)Math.Ceiling((double)maxOutputLength / BytesPerCredit);
            request.CtlCode = ctlCode;
            request.IsFSCtl = true;
            request.FileId = (FileID)handle;
            request.Input = input;
            request.MaxOutputResponse = (uint)maxOutputLength;
            TrySendCommand(request);
            SMB2Command response = WaitForCommand(SMB2CommandName.IOCtl);
            if (response != null)
            {
                if ((response.Header.Status == NTStatus.STATUS_SUCCESS || response.Header.Status == NTStatus.STATUS_BUFFER_OVERFLOW) && response is IOCtlResponse)
                {
                    output = ((IOCtlResponse)response).Output;
                }
                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus Disconnect()
        {
            TreeDisconnectRequest request = new TreeDisconnectRequest();
            TrySendCommand(request);
            SMB2Command response = WaitForCommand(SMB2CommandName.TreeDisconnect);
            if (response != null)
            {
                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        private SMB2Command WaitForCommand(SMB2CommandName commandName)
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