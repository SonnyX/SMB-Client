/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using SMBLibrary.Client;
using SMBLibrary.Services;
using Utilities;

namespace SMBLibrary
{
    public class NamedPipeStore : INtFileStore
    {
        private readonly List<RemoteService> m_services;

        public NamedPipeStore(List<RemoteService> services)
        {
            m_services = services;
        }

        public void CreateFile(out NtHandle handle, out FileStatus fileStatus, string path,
            AccessMask desiredAccess, FileAttributes fileAttributes, ShareAccess shareAccess,
            CreateDisposition createDisposition, CreateOptions createOptions, SecurityContext? securityContext)
        {
            fileStatus = FileStatus.FILE_DOES_NOT_EXIST;
            // It is possible to have a named pipe that does not use RPC (e.g. MS-WSP),
            // However this is not currently needed by our implementation.
            RemoteService? service = GetService(path);
            if (service == null)
                throw new NtStatusException(NTStatus.STATUS_OBJECT_PATH_NOT_FOUND);

            // All instances of a named pipe share the same pipe name, but each instance has its own buffers and handles,
            // and provides a separate conduit for client/server communication.
            using RPCPipeStream stream = new RPCPipeStream(service);
            handle = new FileHandle(path, false, stream, false);
            fileStatus = FileStatus.FILE_OPENED;
        }

        public void CloseFile(NtHandle handle)
        {
            FileHandle fileHandle = (FileHandle)handle;
            fileHandle.Stream.Close();
        }

        private RemoteService? GetService(string path)
        {
            if (path.StartsWith(@"\"))
            {
                path = path[1..];
            }

            return m_services.FirstOrDefault(service => string.Equals(path, service.PipeName, StringComparison.OrdinalIgnoreCase));
        }

        public void ReadFile(out byte[] data, NtHandle handle, long offset, int maxCount)
        {
            data = new byte[maxCount];

            Stream stream = ((FileHandle)handle).Stream;
            int bytesRead = stream.Read(data, 0, maxCount);
            if (bytesRead < maxCount)
            {
                // EOF, we must trim the response data array
                data = ByteReader.ReadBytes(data, 0, bytesRead);
            }
        }

        public void WriteFile(out int numberOfBytesWritten, NtHandle handle, long offset, byte[] data)
        {
            numberOfBytesWritten = 0;

            Stream stream = ((FileHandle)handle).Stream;
            stream.Write(data, 0, data.Length);
            numberOfBytesWritten = data.Length;
        }

        public void FlushFileBuffers(NtHandle handle)
        {
            FileHandle fileHandle = (FileHandle)handle;
            fileHandle.Stream?.Flush();
        }

        public void LockFile(NtHandle? handle, long byteOffset, long length, bool exclusiveLock)
        {
            throw new NtStatusException(NTStatus.STATUS_NOT_SUPPORTED);
        }

        public void UnlockFile(NtHandle? handle, long byteOffset, long length)
        {
            throw new NtStatusException(NTStatus.STATUS_NOT_SUPPORTED);
        }

        public void DeviceIOControl(NtHandle handle, uint ctlCode, byte[] input, out byte[]? output, int maxOutputLength)
        {
            output = null;

            switch (ctlCode)
            {
                case (uint)IoControlCode.FSCTL_PIPE_WAIT:
                    {
                        PipeWaitRequest request;
                        try
                        {
                            request = new PipeWaitRequest(input, 0);
                        }
                        catch
                        {
                            throw new NtStatusException(NTStatus.STATUS_INVALID_PARAMETER);
                        }

                        RemoteService? service = GetService(request.Name);
                        if (service == null)
                        {
                            throw new NtStatusException(NTStatus.STATUS_OBJECT_NAME_NOT_FOUND);
                        }

                        output = new byte[0];
                        return;
                    }
                case (uint)IoControlCode.FSCTL_PIPE_TRANSCEIVE:
                    {
                        WriteFile(out _, handle, 0, input);

                        int messageLength = ((RPCPipeStream)((FileHandle)handle).Stream).MessageLength;
                        ReadFile(out output, handle, 0, maxOutputLength);

                        if (output.Length < messageLength)
                        {
                            throw new NtStatusException(NTStatus.STATUS_BUFFER_OVERFLOW);
                        }

                        return;
                    }
                default:
                    throw new NtStatusException(NTStatus.STATUS_NOT_SUPPORTED);
            }
        }

        public void QueryDirectory(out List<QueryDirectoryFileInformation>? result, NtHandle? directoryHandle, string fileName, FileInformationClass informationClass)
        {
            throw new NtStatusException(NTStatus.STATUS_NOT_SUPPORTED);
        }

        public void GetFileInformation(out FileInformation? result, NtHandle? handle,
            FileInformationClass informationClass)
        {
            switch (informationClass)
            {
                case FileInformationClass.FileBasicInformation:
                    {
                        FileBasicInformation information = new FileBasicInformation
                        {
                            FileAttributes = FileAttributes.Temporary
                        };
                        result = information;
                        return;
                    }
                case FileInformationClass.FileStandardInformation:
                    {
                        FileStandardInformation information = new FileStandardInformation
                        {
                            DeletePending = false
                        };
                        result = information;
                        return;
                    }
                case FileInformationClass.FileNetworkOpenInformation:
                    {
                        FileNetworkOpenInformation information = new FileNetworkOpenInformation
                        {
                            FileAttributes = FileAttributes.Temporary
                        };
                        result = information;
                        return;
                    }
                default:
                    result = null;
                    throw new NtStatusException(NTStatus.STATUS_INVALID_INFO_CLASS);
            }
        }

        public void SetFileInformation(NtHandle? handle, FileInformation information)
        {
            throw new NtStatusException(NTStatus.STATUS_NOT_SUPPORTED);
        }

        public void GetFileSystemInformation(out FileSystemInformation? result, FileSystemInformationClass informationClass)
        {
            result = null;
            throw new NtStatusException(NTStatus.STATUS_NOT_SUPPORTED);
        }

        public void SetFileSystemInformation(FileSystemInformation information)
        {
            throw new NtStatusException(NTStatus.STATUS_NOT_SUPPORTED);
        }

        public void GetSecurityInformation(out SecurityDescriptor? result, NtHandle? handle, SecurityInformation securityInformation)
        {
            result = null;
            throw new NtStatusException(NTStatus.STATUS_NOT_SUPPORTED);
        }

        public void SetSecurityInformation(NtHandle? handle, SecurityInformation securityInformation, SecurityDescriptor securityDescriptor)
        {
            throw new NtStatusException(NTStatus.STATUS_NOT_SUPPORTED);
        }

        public void NotifyChange(out object? ioRequest, NtHandle? handle, NotifyChangeFilter completionFilter, bool watchTree, int outputBufferSize, OnNotifyChangeCompleted onNotifyChangeCompleted, object context)
        {
            ioRequest = null;
            throw new NtStatusException(NTStatus.STATUS_NOT_SUPPORTED);
        }

        public void Cancel(object? ioRequest)
        {
            throw new NtStatusException(NTStatus.STATUS_NOT_SUPPORTED);
        }
    }
}