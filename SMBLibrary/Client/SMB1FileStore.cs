/* Copyright (C) 2014-2019 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using SMBLibrary.SMB1;

namespace SMBLibrary.Client
{
    public class SMB1FileStore : ISMBFileStore
    {
        private readonly SMB1Client m_client;
        private readonly ushort m_treeID;

        public SMB1FileStore(SMB1Client client, ushort treeID)
        {
            m_client = client;
            m_treeID = treeID;
        }

        public NTStatus CreateFile(out object handle, out FileStatus fileStatus, string path, AccessMask desiredAccess, FileAttributes fileAttributes, ShareAccess shareAccess, CreateDisposition createDisposition, CreateOptions createOptions, SecurityContext securityContext)
        {
            handle = null;
            fileStatus = FileStatus.FILE_DOES_NOT_EXIST;
            NTCreateAndXRequest request = new NTCreateAndXRequest
            {
                FileName = path,
                DesiredAccess = desiredAccess,
                ExtFileAttributes = ToExtendedFileAttributes(fileAttributes),
                ShareAccess = shareAccess,
                CreateDisposition = createDisposition,
                CreateOptions = createOptions,
                ImpersonationLevel = ImpersonationLevel.Impersonation
            };

            TrySendMessage(request);
            SMB1Message reply = m_client.WaitForMessage(CommandName.SMB_COM_NT_CREATE_ANDX);
            if (reply != null)
            {
                if (reply.Commands[0] is NTCreateAndXResponse)
                {
                    NTCreateAndXResponse response = reply.Commands[0] as NTCreateAndXResponse;
                    handle = response.FID;
                    fileStatus = ToFileStatus(response.CreateDisposition);
                    return reply.Header.Status;
                }

                if (reply.Commands[0] is ErrorResponse)
                {
                    return reply.Header.Status;
                }
            }
            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus CloseFile(object handle)
        {
            CloseRequest request = new CloseRequest
            {
                FID = (ushort)handle
            };
            TrySendMessage(request);
            SMB1Message reply = m_client.WaitForMessage(CommandName.SMB_COM_CLOSE);
            if (reply != null)
            {
                return reply.Header.Status;
            }
            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus ReadFile(out byte[] data, object handle, long offset, int maxCount)
        {
            data = null;
            ReadAndXRequest request = new ReadAndXRequest
            {
                FID = (ushort)handle,
                Offset = (ulong)offset,
                MaxCountLarge = (uint)maxCount
            };

            TrySendMessage(request);
            SMB1Message reply = m_client.WaitForMessage(CommandName.SMB_COM_READ_ANDX);
            if (reply == null)
                return NTStatus.STATUS_INVALID_SMB;

            if (reply.Header.Status == NTStatus.STATUS_SUCCESS && reply.Commands[0] is ReadAndXResponse response)
                data = response.Data;

            return reply.Header.Status;
        }

        public NTStatus WriteFile(out int numberOfBytesWritten, object handle, long offset, byte[] data)
        {
            numberOfBytesWritten = 0;
            WriteAndXRequest request = new WriteAndXRequest
            {
                FID = (ushort)handle,
                Offset = (ulong)offset,
                Data = data
            };

            TrySendMessage(request);
            SMB1Message reply = m_client.WaitForMessage(CommandName.SMB_COM_WRITE_ANDX);
            if (reply == null)
                return NTStatus.STATUS_INVALID_SMB;

            if (reply.Header.Status == NTStatus.STATUS_SUCCESS && reply.Commands[0] is WriteAndXResponse response)
                numberOfBytesWritten = (int)response.Count;

            return reply.Header.Status;
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
            throw new NotImplementedException();
        }

        public NTStatus QueryDirectory(out List<FindInformation> result, string fileName, FindInformationLevel informationLevel)
        {
            result = null;
            int maxOutputLength = 4096;
            Transaction2FindFirst2Request subcommand = new Transaction2FindFirst2Request
            {
                SearchAttributes = SMBFileAttributes.Hidden | SMBFileAttributes.System | SMBFileAttributes.Directory,
                SearchCount = ushort.MaxValue,
                Flags = FindFlags.SMB_FIND_CLOSE_AT_EOS,
                InformationLevel = informationLevel,
                FileName = fileName
            };

            Transaction2Request request = new Transaction2Request
            {
                Setup = subcommand.GetSetup(),
                TransParameters = subcommand.GetParameters(m_client.Unicode),
                TransData = subcommand.GetData(m_client.Unicode)
            };
            request.TotalDataCount = (ushort)request.TransData.Length;
            request.TotalParameterCount = (ushort)request.TransParameters.Length;
            request.MaxParameterCount = Transaction2FindFirst2Response.ParametersLength;
            request.MaxDataCount = (ushort)maxOutputLength;

            TrySendMessage(request);
            SMB1Message reply = m_client.WaitForMessage(CommandName.SMB_COM_TRANSACTION2);
            if (reply == null)
                return NTStatus.STATUS_INVALID_SMB;

            if (reply.Header.Status != NTStatus.STATUS_SUCCESS || !(reply.Commands[0] is Transaction2Response))
                return reply.Header.Status;

            result = new List<FindInformation>();
            Transaction2Response response = (Transaction2Response)reply.Commands[0];
            Transaction2FindFirst2Response subcommandResponse = new Transaction2FindFirst2Response(response.TransParameters, response.TransData);
            FindInformationList findInformationList = subcommandResponse.GetFindInformationList(subcommand.InformationLevel, reply.Header.UnicodeFlag);
            result.AddRange(findInformationList);
            bool endOfSearch = subcommandResponse.EndOfSearch;
            while (!endOfSearch)
            {
                Transaction2FindNext2Request nextSubcommand = new Transaction2FindNext2Request
                {
                    SID = subcommandResponse.SID,
                    SearchCount = ushort.MaxValue,
                    Flags = FindFlags.SMB_FIND_CLOSE_AT_EOS | FindFlags.SMB_FIND_CONTINUE_FROM_LAST,
                    InformationLevel = informationLevel,
                    FileName = fileName
                };

                request = new Transaction2Request
                {
                    Setup = nextSubcommand.GetSetup(),
                    TransParameters = nextSubcommand.GetParameters(m_client.Unicode),
                    TransData = nextSubcommand.GetData(m_client.Unicode)
                };
                request.TotalDataCount = (ushort)request.TransData.Length;
                request.TotalParameterCount = (ushort)request.TransParameters.Length;
                request.MaxParameterCount = Transaction2FindNext2Response.ParametersLength;
                request.MaxDataCount = (ushort)maxOutputLength;

                TrySendMessage(request);
                reply = m_client.WaitForMessage(CommandName.SMB_COM_TRANSACTION2);
                if (reply.Header.Status == NTStatus.STATUS_SUCCESS && reply.Commands[0] is Transaction2Response transaction2Response)
                {
                    Transaction2FindNext2Response nextSubcommandResponse = new Transaction2FindNext2Response(transaction2Response.TransParameters, transaction2Response.TransData);
                    findInformationList = nextSubcommandResponse.GetFindInformationList(subcommand.InformationLevel, reply.Header.UnicodeFlag);
                    result.AddRange(findInformationList);
                    endOfSearch = nextSubcommandResponse.EndOfSearch;
                }
                else
                {
                    endOfSearch = true;
                }
            }
            return reply.Header.Status;
        }

        public NTStatus GetFileInformation(out FileInformation result, object handle, FileInformationClass informationClass)
        {
            result = null;
            if (m_client.InfoLevelPassthrough)
            {
                int maxOutputLength = 4096;
                Transaction2QueryFileInformationRequest subcommand = new Transaction2QueryFileInformationRequest
                {
                    FID = (ushort)handle,
                    FileInformationClass = informationClass
                };

                Transaction2Request request = new Transaction2Request
                {
                    Setup = subcommand.GetSetup(),
                    TransParameters = subcommand.GetParameters(m_client.Unicode),
                    TransData = subcommand.GetData(m_client.Unicode)
                };
                request.TotalDataCount = (ushort)request.TransData.Length;
                request.TotalParameterCount = (ushort)request.TransParameters.Length;
                request.MaxParameterCount = Transaction2QueryFileInformationResponse.ParametersLength;
                request.MaxDataCount = (ushort)maxOutputLength;

                TrySendMessage(request);
                SMB1Message reply = m_client.WaitForMessage(CommandName.SMB_COM_TRANSACTION2);
                if (reply == null)
                    return NTStatus.STATUS_INVALID_SMB;

                if (reply.Header.Status != NTStatus.STATUS_SUCCESS || !(reply.Commands[0] is Transaction2Response transaction2Response))
                    return reply.Header.Status;

                Transaction2QueryFileInformationResponse subcommandResponse = new Transaction2QueryFileInformationResponse(transaction2Response.TransParameters, transaction2Response.TransData);
                if (informationClass == FileInformationClass.FileAllInformation)
                {
                    // Windows implementations return SMB_QUERY_FILE_ALL_INFO when a client specifies native NT passthrough level "FileAllInformation".
                    QueryInformation queryFileAllInfo = subcommandResponse.GetQueryInformation(QueryInformationLevel.SMB_QUERY_FILE_ALL_INFO);
                    result = QueryInformationHelper.ToFileInformation(queryFileAllInfo);
                }
                else
                {
                    result = subcommandResponse.GetFileInformation(informationClass);
                }
                return reply.Header.Status;
            }

            QueryInformationLevel informationLevel = QueryInformationHelper.ToFileInformationLevel(informationClass);
            NTStatus status = GetFileInformation(out QueryInformation queryInformation, handle, informationLevel);
            if (status == NTStatus.STATUS_SUCCESS)
            {
                result = QueryInformationHelper.ToFileInformation(queryInformation);
            }
            return status;
        }

        public NTStatus GetFileInformation(out QueryInformation result, object handle, QueryInformationLevel informationLevel)
        {
            result = null;
            int maxOutputLength = 4096;
            Transaction2QueryFileInformationRequest subcommand = new Transaction2QueryFileInformationRequest
            {
                FID = (ushort)handle,
                QueryInformationLevel = informationLevel
            };

            Transaction2Request request = new Transaction2Request
            {
                Setup = subcommand.GetSetup(),
                TransParameters = subcommand.GetParameters(m_client.Unicode),
                TransData = subcommand.GetData(m_client.Unicode)
            };
            request.TotalDataCount = (ushort)request.TransData.Length;
            request.TotalParameterCount = (ushort)request.TransParameters.Length;
            request.MaxParameterCount = Transaction2QueryFileInformationResponse.ParametersLength;
            request.MaxDataCount = (ushort)maxOutputLength;

            TrySendMessage(request);
            SMB1Message reply = m_client.WaitForMessage(CommandName.SMB_COM_TRANSACTION2);
            if (reply == null)
                return NTStatus.STATUS_INVALID_SMB;
            if (reply.Header.Status != NTStatus.STATUS_SUCCESS || !(reply.Commands[0] is Transaction2Response))
                return reply.Header.Status;

            Transaction2Response response = (Transaction2Response)reply.Commands[0];
            Transaction2QueryFileInformationResponse subcommandResponse = new Transaction2QueryFileInformationResponse(response.TransParameters, response.TransData);
            result = subcommandResponse.GetQueryInformation(informationLevel);
            return reply.Header.Status;
        }

        public NTStatus SetFileInformation(object handle, FileInformation information)
        {
            if (m_client.InfoLevelPassthrough)
            {
                if (information is FileRenameInformationType2 fileRenameInformationType2)
                {
                    FileRenameInformationType1 informationType1 = new FileRenameInformationType1
                    {
                        FileName = fileRenameInformationType2.FileName,
                        ReplaceIfExists = fileRenameInformationType2.ReplaceIfExists,
                        RootDirectory = (uint)fileRenameInformationType2.RootDirectory
                    };
                    information = informationType1;
                }

                int maxOutputLength = 4096;
                Transaction2SetFileInformationRequest subcommand = new Transaction2SetFileInformationRequest
                {
                    FID = (ushort)handle
                };
                subcommand.SetInformation(information);

                Transaction2Request request = new Transaction2Request
                {
                    Setup = subcommand.GetSetup(),
                    TransParameters = subcommand.GetParameters(m_client.Unicode),
                    TransData = subcommand.GetData(m_client.Unicode)
                };
                request.TotalDataCount = (ushort)request.TransData.Length;
                request.TotalParameterCount = (ushort)request.TransParameters.Length;
                request.MaxParameterCount = Transaction2SetFileInformationResponse.ParametersLength;
                request.MaxDataCount = (ushort)maxOutputLength;

                TrySendMessage(request);
                SMB1Message reply = m_client.WaitForMessage(CommandName.SMB_COM_TRANSACTION2);
                if (reply != null)
                {
                    return reply.Header.Status;
                }
                return NTStatus.STATUS_INVALID_SMB;
            }

            throw new NotSupportedException("Server does not support InfoLevelPassthrough");
        }

        public NTStatus SetFileInformation(object handle, SetInformation information)
        {
            int maxOutputLength = 4096;
            Transaction2SetFileInformationRequest subcommand = new Transaction2SetFileInformationRequest
            {
                FID = (ushort)handle
            };
            subcommand.SetInformation(information);

            Transaction2Request request = new Transaction2Request
            {
                Setup = subcommand.GetSetup(),
                TransParameters = subcommand.GetParameters(m_client.Unicode),
                TransData = subcommand.GetData(m_client.Unicode)
            };
            request.TotalDataCount = (ushort)request.TransData.Length;
            request.TotalParameterCount = (ushort)request.TransParameters.Length;
            request.MaxParameterCount = Transaction2SetFileInformationResponse.ParametersLength;
            request.MaxDataCount = (ushort)maxOutputLength;

            TrySendMessage(request);
            SMB1Message reply = m_client.WaitForMessage(CommandName.SMB_COM_TRANSACTION2);
            if (reply != null)
            {
                return reply.Header.Status;
            }
            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus GetFileSystemInformation(out FileSystemInformation result, FileSystemInformationClass informationClass)
        {
            if (m_client.InfoLevelPassthrough)
            {
                result = null;
                int maxOutputLength = 4096;
                Transaction2QueryFSInformationRequest subcommand = new Transaction2QueryFSInformationRequest
                {
                    FileSystemInformationClass = informationClass
                };

                Transaction2Request request = new Transaction2Request
                {
                    Setup = subcommand.GetSetup(),
                    TransParameters = subcommand.GetParameters(m_client.Unicode),
                    TransData = subcommand.GetData(m_client.Unicode)
                };
                request.TotalDataCount = (ushort)request.TransData.Length;
                request.TotalParameterCount = (ushort)request.TransParameters.Length;
                request.MaxParameterCount = Transaction2QueryFSInformationResponse.ParametersLength;
                request.MaxDataCount = (ushort)maxOutputLength;

                TrySendMessage(request);
                SMB1Message reply = m_client.WaitForMessage(CommandName.SMB_COM_TRANSACTION2);
                if (reply == null)
                    return NTStatus.STATUS_INVALID_SMB;

                if (reply.Header.Status != NTStatus.STATUS_SUCCESS || !(reply.Commands[0] is Transaction2Response transaction2Response))
                    return reply.Header.Status;

                Transaction2QueryFSInformationResponse subcommandResponse = new Transaction2QueryFSInformationResponse(transaction2Response.TransData);
                result = subcommandResponse.GetFileSystemInformation(informationClass);
                return reply.Header.Status;
            }

            throw new NotSupportedException("Server does not support InfoLevelPassthrough");
        }

        public NTStatus GetFileSystemInformation(out QueryFSInformation result, QueryFSInformationLevel informationLevel)
        {
            result = null;
            int maxOutputLength = 4096;
            Transaction2QueryFSInformationRequest subcommand = new Transaction2QueryFSInformationRequest
            {
                QueryFSInformationLevel = informationLevel
            };

            Transaction2Request request = new Transaction2Request
            {
                Setup = subcommand.GetSetup(),
                TransParameters = subcommand.GetParameters(m_client.Unicode),
                TransData = subcommand.GetData(m_client.Unicode)
            };
            request.TotalDataCount = (ushort)request.TransData.Length;
            request.TotalParameterCount = (ushort)request.TransParameters.Length;
            request.MaxParameterCount = Transaction2QueryFSInformationResponse.ParametersLength;
            request.MaxDataCount = (ushort)maxOutputLength;

            TrySendMessage(request);
            SMB1Message reply = m_client.WaitForMessage(CommandName.SMB_COM_TRANSACTION2);
            if (reply == null)
                return NTStatus.STATUS_INVALID_SMB;
            if (reply.Header.Status != NTStatus.STATUS_SUCCESS || !(reply.Commands[0] is Transaction2Response))
                return reply.Header.Status;

            Transaction2Response response = (Transaction2Response)reply.Commands[0];
            Transaction2QueryFSInformationResponse subcommandResponse = new Transaction2QueryFSInformationResponse(response.TransData);
            result = subcommandResponse.GetQueryFSInformation(informationLevel);
            return reply.Header.Status;
        }

        public NTStatus SetFileSystemInformation(FileSystemInformation information)
        {
            throw new NotImplementedException();
        }

        public NTStatus GetSecurityInformation(out SecurityDescriptor result, object handle, SecurityInformation securityInformation)
        {
            result = null;
            int maxOutputLength = 4096;
            NTTransactQuerySecurityDescriptorRequest subcommand = new NTTransactQuerySecurityDescriptorRequest
            {
                FID = (ushort)handle,
                SecurityInfoFields = securityInformation
            };

            NTTransactRequest request = new NTTransactRequest
            {
                Function = subcommand.SubcommandName,
                Setup = subcommand.GetSetup(),
                TransParameters = subcommand.GetParameters(m_client.Unicode),
                TransData = subcommand.GetData()
            };
            request.TotalDataCount = (uint)request.TransData.Length;
            request.TotalParameterCount = (uint)request.TransParameters.Length;
            request.MaxParameterCount = NTTransactQuerySecurityDescriptorResponse.ParametersLength;
            request.MaxDataCount = (uint)maxOutputLength;

            TrySendMessage(request);
            SMB1Message reply = m_client.WaitForMessage(CommandName.SMB_COM_NT_TRANSACT);
            if (reply != null)
            {
                if (reply.Header.Status != NTStatus.STATUS_SUCCESS || !(reply.Commands[0] is NTTransactResponse ntTransactResponse))
                    return reply.Header.Status;
                NTTransactQuerySecurityDescriptorResponse subcommandResponse = new NTTransactQuerySecurityDescriptorResponse(ntTransactResponse.TransParameters, ntTransactResponse.TransData);
                result = subcommandResponse.SecurityDescriptor;
                return reply.Header.Status;
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
            if ((IoControlCode)ctlCode == IoControlCode.FSCTL_PIPE_TRANSCEIVE)
            {
                return FsCtlPipeTranscieve(handle, input, out output, maxOutputLength);
            }

            output = null;
            NTTransactIOCTLRequest subcommand = new NTTransactIOCTLRequest
            {
                FID = (ushort)handle,
                FunctionCode = ctlCode,
                IsFsctl = true,
                Data = input
            };

            NTTransactRequest request = new NTTransactRequest
            {
                Function = subcommand.SubcommandName,
                Setup = subcommand.GetSetup(),
                TransParameters = subcommand.GetParameters(m_client.Unicode),
                TransData = subcommand.GetData()
            };
            request.TotalDataCount = (uint)request.TransData.Length;
            request.TotalParameterCount = (uint)request.TransParameters.Length;
            request.MaxParameterCount = NTTransactIOCTLResponse.ParametersLength;
            request.MaxDataCount = (uint)maxOutputLength;

            TrySendMessage(request);
            SMB1Message reply = m_client.WaitForMessage(CommandName.SMB_COM_NT_TRANSACT);
            if (reply != null)
            {
                if (reply.Header.Status == NTStatus.STATUS_SUCCESS && reply.Commands[0] is NTTransactResponse ntTransactResponse)
                {
                    NTTransactIOCTLResponse subcommandResponse = new NTTransactIOCTLResponse(ntTransactResponse.Setup, ntTransactResponse.TransData);
                    output = subcommandResponse.Data;
                }
                return reply.Header.Status;
            }
            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus FsCtlPipeTranscieve(object handle, byte[] input, out byte[] output, int maxOutputLength)
        {
            output = null;
            TransactionTransactNamedPipeRequest subcommand = new TransactionTransactNamedPipeRequest
            {
                FID = (ushort)handle,
                WriteData = input
            };

            TransactionRequest request = new TransactionRequest
            {
                Setup = subcommand.GetSetup(),
                TransParameters = subcommand.GetParameters(),
                TransData = subcommand.GetData(m_client.Unicode)
            };
            request.TotalDataCount = (ushort)request.TransData.Length;
            request.TotalParameterCount = (ushort)request.TransParameters.Length;
            request.MaxParameterCount = TransactionTransactNamedPipeResponse.ParametersLength;
            request.MaxDataCount = (ushort)maxOutputLength;
            request.Name = @"\PIPE\";

            TrySendMessage(request);
            SMB1Message reply = m_client.WaitForMessage(CommandName.SMB_COM_TRANSACTION);
            if (reply != null)
            {
                if (reply.Header.Status == NTStatus.STATUS_SUCCESS && reply.Commands[0] is TransactionResponse transactionResponse)
                {
                    TransactionTransactNamedPipeResponse subcommandResponse = new TransactionTransactNamedPipeResponse(transactionResponse.TransData);
                    output = subcommandResponse.ReadData;
                }
                return reply.Header.Status;
            }
            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus Disconnect()
        {
            TreeDisconnectRequest request = new TreeDisconnectRequest();
            TrySendMessage(request);
            SMB1Message reply = m_client.WaitForMessage(CommandName.SMB_COM_TREE_DISCONNECT);
            if (reply != null)
            {
                return reply.Header.Status;
            }
            return NTStatus.STATUS_INVALID_SMB;
        }

        private void TrySendMessage(SMB1Command request)
        {
            m_client.TrySendMessage(request, m_treeID);
        }

        public uint MaxReadSize => m_client.MaxReadSize;

        public uint MaxWriteSize => m_client.MaxWriteSize;

        private static ExtendedFileAttributes ToExtendedFileAttributes(FileAttributes fileAttributes)
        {
            // We only return flags that can be used with NtCreateFile
            ExtendedFileAttributes extendedFileAttributes = ExtendedFileAttributes.ReadOnly |
                                                            ExtendedFileAttributes.Hidden |
                                                            ExtendedFileAttributes.System |
                                                            ExtendedFileAttributes.Archive |
                                                            ExtendedFileAttributes.Normal |
                                                            ExtendedFileAttributes.Temporary |
                                                            ExtendedFileAttributes.Offline |
                                                            ExtendedFileAttributes.Encrypted;
            return (extendedFileAttributes & (ExtendedFileAttributes)fileAttributes);
        }

        private static FileStatus ToFileStatus(CreateDisposition createDisposition)
        {
            return createDisposition switch
            {
                CreateDisposition.FILE_SUPERSEDE => FileStatus.FILE_SUPERSEDED,
                CreateDisposition.FILE_OPEN => FileStatus.FILE_OPENED,
                CreateDisposition.FILE_CREATE => FileStatus.FILE_CREATED,
                CreateDisposition.FILE_OPEN_IF => FileStatus.FILE_OVERWRITTEN,
                CreateDisposition.FILE_OVERWRITE => FileStatus.FILE_EXISTS,
                CreateDisposition.FILE_OVERWRITE_IF => FileStatus.FILE_DOES_NOT_EXIST,
                _ => FileStatus.FILE_OPENED
            };
        }
    }
}