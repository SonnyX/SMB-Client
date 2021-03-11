/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;

namespace SMBLibrary
{
    public delegate void OnNotifyChangeCompleted(NTStatus status, byte[] buffer, object context);

    /// <summary>
    /// A file store (a.k.a. object store) interface to allow access to a file system or a named pipe in an NT-like manner dictated by the SMB protocol.
    /// </summary>
    public interface INtFileStore
    {
        void CreateFile(out NtHandle handle, out FileStatus fileStatus, string path, AccessMask desiredAccess, FileAttributes fileAttributes, ShareAccess shareAccess, CreateDisposition createDisposition, CreateOptions createOptions, SecurityContext? securityContext);

        void CloseFile(NtHandle handle);

        void ReadFile(out byte[]? data, NtHandle handle, long offset, int maxCount);

        void WriteFile(out int numberOfBytesWritten, NtHandle handle, long offset, byte[] data);

        void FlushFileBuffers(NtHandle handle);

        void LockFile(NtHandle handle, long byteOffset, long length, bool exclusiveLock);

        void UnlockFile(NtHandle handle, long byteOffset, long length);

        void QueryDirectory(out List<QueryDirectoryFileInformation>? result, NtHandle handle, string fileName, FileInformationClass informationClass);

        void GetFileInformation(out FileInformation? result, NtHandle handle, FileInformationClass informationClass);

        void SetFileInformation(NtHandle handle, FileInformation information);

        void GetFileSystemInformation(out FileSystemInformation? result, FileSystemInformationClass informationClass);

        void SetFileSystemInformation(FileSystemInformation information);

        void GetSecurityInformation(out SecurityDescriptor? result, NtHandle handle, SecurityInformation securityInformation);

        void SetSecurityInformation(NtHandle handle, SecurityInformation securityInformation, SecurityDescriptor securityDescriptor);

        /// <summary>
        /// Monitor the contents of a directory (and its subdirectories) by using change notifications.
        /// When something changes within the directory being watched this operation is completed.
        /// </summary>
        /// <returns>
        /// STATUS_PENDING - The directory is being watched, change notification will be provided using callback method.
        /// STATUS_NOT_SUPPORTED - The underlying object store does not support change notifications.
        /// STATUS_INVALID_HANDLE - The handle supplied is invalid.
        /// </returns>
        void NotifyChange(out object? ioRequest, NtHandle handle, NotifyChangeFilter completionFilter, bool watchTree, int outputBufferSize, OnNotifyChangeCompleted onNotifyChangeCompleted, object context);

        void Cancel(object ioRequest);

        void DeviceIOControl(NtHandle handle, uint ctlCode, byte[] input, out byte[]? output, int maxOutputLength);
    }
}