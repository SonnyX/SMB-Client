/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;
using SMBLibrary.NetBios;
using SMBLibrary.Server.SMB1;
using SMBLibrary.SMB1;
using Utilities;

namespace SMBLibrary.Server
{
    public partial class SMBServer
    {
        private void ProcessSMB1Message(SMB1Message message, ref ConnectionState state)
        {
            SMB1Header header = new SMB1Header();
            PrepareResponseHeader(header, message.Header);
            List<SMB1Command> responses = new List<SMB1Command>();

            bool isBatchedRequest = (message.Commands.Count > 1);
            foreach (SMB1Command command in message.Commands)
            {
                List<SMB1Command> commandResponses = ProcessSMB1Command(header, command, ref state);
                responses.AddRange(commandResponses);

                if (header.Status != NTStatus.STATUS_SUCCESS)
                {
                    break;
                }
            }

            if (isBatchedRequest)
            {
                if (responses.Count > 0)
                {
                    // The server MUST batch the response into an AndX Response chain.
                    SMB1Message reply = new SMB1Message
                    {
                        Header = header
                    };
                    for (int index = 0; index < responses.Count; index++)
                    {
                        if (reply.Commands.Count == 0 ||
                            reply.Commands[^1] is SMBAndXCommand)
                        {
                            reply.Commands.Add(responses[index]);
                            responses.RemoveAt(index);
                            index--;
                        }
                        else
                        {
                            break;
                        }
                    }
                    EnqueueMessage(state, reply);
                }
            }

            foreach (SMB1Command response in responses)
            {
                SMB1Message reply = new SMB1Message
                {
                    Header = header
                };
                reply.Commands.Add(response);
                EnqueueMessage(state, reply);
            }
        }

        /// <summary>
        /// May return an empty list
        /// </summary>
        private List<SMB1Command> ProcessSMB1Command(SMB1Header header, SMB1Command command, ref ConnectionState state)
        {
            if (state.Dialect == SMBDialect.NotSet)
            {
                if (command is NegotiateRequest request)
                {
                    if (!request.Dialects.Contains(NTLanManagerDialect))
                        return new NegotiateResponseNotSupported();

                    state = new SMB1ConnectionState(state)
                    {
                        Dialect = SMBDialect.NTLM012
                    };
                    m_connectionManager.AddConnection(state);
                    if (EnableExtendedSecurity && header.ExtendedSecurityFlag)
                    {
                        return NegotiateHelper.GetNegotiateResponseExtended(request, m_serverGuid);
                    }

                    return NegotiateHelper.GetNegotiateResponse(request, m_securityProvider, state);
                }

                // [MS-CIFS] An SMB_COM_NEGOTIATE exchange MUST be completed before any other SMB messages are sent to the server
                header.Status = NTStatus.STATUS_INVALID_SMB;
                return new ErrorResponse(command.CommandName);
            }

            if (command is NegotiateRequest)
            {
                // There MUST be only one SMB_COM_NEGOTIATE exchange per SMB connection.
                // Subsequent SMB_COM_NEGOTIATE requests received by the server MUST be rejected with error responses.
                header.Status = NTStatus.STATUS_INVALID_SMB;
                return new ErrorResponse(command.CommandName);
            }
            return ProcessSMB1Command(header, command, (SMB1ConnectionState)state);
        }

        private List<SMB1Command> ProcessSMB1Command(SMB1Header header, SMB1Command command, SMB1ConnectionState state)
        {
            switch (command)
            {
                case SessionSetupAndXRequest xRequest:
                    {
                        SessionSetupAndXRequest request = xRequest;
                        state.MaxBufferSize = request.MaxBufferSize;
                        return SessionSetupHelper.GetSessionSetupResponse(header, request, m_securityProvider, state);
                    }
                case SessionSetupAndXRequestExtended extended:
                    {
                        SessionSetupAndXRequestExtended request = extended;
                        state.MaxBufferSize = request.MaxBufferSize;
                        return SessionSetupHelper.GetSessionSetupResponseExtended(header, request, m_securityProvider, state);
                    }
                case EchoRequest request:
                    return EchoHelper.GetEchoResponse(request);
            }

            SMB1Session session = state.GetSession(header.UID);
            if (session == null)
            {
                header.Status = NTStatus.STATUS_USER_SESSION_DELETED;
                return new ErrorResponse(command.CommandName);
            }

            switch (command)
            {
                case TreeConnectAndXRequest request:
                    return TreeConnectHelper.GetTreeConnectResponse(header, request, state, m_services, m_shares);

                case LogoffAndXRequest _:
                    state.LogToServer(Severity.Information, "Logoff: User '{0}' logged off. (UID: {1})", session.UserName, header.UID);
                    m_securityProvider.DeleteSecurityContext(ref session.SecurityContext.AuthenticationContext);
                    state.RemoveSession(header.UID);
                    return new LogoffAndXResponse();
            }

            ISMBShare share = session.GetConnectedTree(header.TID);
            if (share == null)
            {
                state.LogToServer(Severity.Verbose, "{0} failed. Invalid TID (UID: {1}, TID: {2}).", command.CommandName, header.UID, header.TID);
                header.Status = NTStatus.STATUS_SMB_BAD_TID;
                return new ErrorResponse(command.CommandName);
            }

            switch (command)
            {
                case CreateDirectoryRequest request:
                    return FileStoreResponseHelper.GetCreateDirectoryResponse(header, request, share, state);

                case DeleteDirectoryRequest request:
                    return FileStoreResponseHelper.GetDeleteDirectoryResponse(header, request, share, state);

                case CloseRequest request:
                    return CloseHelper.GetCloseResponse(header, request, share, state);

                case FlushRequest request:
                    return ReadWriteResponseHelper.GetFlushResponse(header, request, share, state);

                case DeleteRequest request:
                    return FileStoreResponseHelper.GetDeleteResponse(header, request, share, state);

                case RenameRequest request:
                    return FileStoreResponseHelper.GetRenameResponse(header, request, share, state);

                case QueryInformationRequest request:
                    return FileStoreResponseHelper.GetQueryInformationResponse(header, request, share, state);

                case SetInformationRequest request:
                    return FileStoreResponseHelper.GetSetInformationResponse(header, request, share, state);

                case ReadRequest request:
                    return ReadWriteResponseHelper.GetReadResponse(header, request, share, state);

                case WriteRequest request:
                    return ReadWriteResponseHelper.GetWriteResponse(header, request, share, state);

                case CheckDirectoryRequest request:
                    return FileStoreResponseHelper.GetCheckDirectoryResponse(header, request, share, state);

                case WriteRawRequest _:
                    // [MS-CIFS] 3.3.5.26 - Receiving an SMB_COM_WRITE_RAW Request:
                    // the server MUST verify that the Server.Capabilities include CAP_RAW_MODE,
                    // If an error is detected [..] the Write Raw operation MUST fail and
                    // the server MUST return a Final Server Response [..] with the Count field set to zero.
                    return new WriteRawFinalResponse();

                case SetInformation2Request request:
                    return FileStoreResponseHelper.GetSetInformation2Response(header, request, share, state);

                case LockingAndXRequest request:
                    return LockingHelper.GetLockingAndXResponse(header, request, share, state);

                case OpenAndXRequest request:
                    return OpenAndXHelper.GetOpenAndXResponse(header, request, share, state);

                case ReadAndXRequest request:
                    return ReadWriteResponseHelper.GetReadResponse(header, request, share, state);

                case WriteAndXRequest request:
                    return ReadWriteResponseHelper.GetWriteResponse(header, request, share, state);

                case FindClose2Request request:
                    return CloseHelper.GetFindClose2Response(header, request, state);

                case TreeDisconnectRequest _:
                    return TreeConnectHelper.GetTreeDisconnectResponse(header, share, state);
                // Both TransactionRequest and Transaction2Request
                case TransactionRequest request:
                    return TransactionHelper.GetTransactionResponse(header, request, share, state);
                // Both TransactionSecondaryRequest and Transaction2SecondaryRequest
                case TransactionSecondaryRequest request:
                    return TransactionHelper.GetTransactionResponse(header, request, share, state);

                case NTTransactRequest request:
                    return NTTransactHelper.GetNTTransactResponse(header, request, share, state);

                case NTTransactSecondaryRequest request:
                    return NTTransactHelper.GetNTTransactResponse(header, request, share, state);

                case NTCreateAndXRequest request:
                    return NTCreateHelper.GetNTCreateResponse(header, request, share, state);

                case NTCancelRequest _:
                    CancelHelper.ProcessNTCancelRequest(header, share, state);
                    // [MS-CIFS] The SMB_COM_NT_CANCEL command MUST NOT send a response.
                    return new List<SMB1Command>();

                default:
                    header.Status = NTStatus.STATUS_SMB_BAD_COMMAND;
                    return new ErrorResponse(command.CommandName);
            }
        }

        internal static void EnqueueMessage(ConnectionState state, SMB1Message response)
        {
            SessionMessagePacket packet = new SessionMessagePacket
            {
                Trailer = response.GetBytes()
            };
            state.SendQueue.Enqueue(packet);
            state.LogToServer(Severity.Verbose, "SMB1 message queued: {0} responses, First response: {1}, Packet length: {2}", response.Commands.Count, response.Commands[0].CommandName.ToString(), packet.Length);
        }

        private static void PrepareResponseHeader(SMB1Header responseHeader, SMB1Header requestHeader)
        {
            responseHeader.Status = NTStatus.STATUS_SUCCESS;
            responseHeader.Flags = HeaderFlags.CaseInsensitive | HeaderFlags.CanonicalizedPaths | HeaderFlags.Reply;
            responseHeader.Flags2 = HeaderFlags2.NTStatusCode;
            if ((requestHeader.Flags2 & HeaderFlags2.LongNamesAllowed) > 0)
            {
                responseHeader.Flags2 |= HeaderFlags2.LongNamesAllowed | HeaderFlags2.LongNameUsed;
            }
            if ((requestHeader.Flags2 & HeaderFlags2.ExtendedAttributes) > 0)
            {
                responseHeader.Flags2 |= HeaderFlags2.ExtendedAttributes;
            }
            if ((requestHeader.Flags2 & HeaderFlags2.ExtendedSecurity) > 0)
            {
                responseHeader.Flags2 |= HeaderFlags2.ExtendedSecurity;
            }
            if ((requestHeader.Flags2 & HeaderFlags2.Unicode) > 0)
            {
                responseHeader.Flags2 |= HeaderFlags2.Unicode;
            }
            responseHeader.MID = requestHeader.MID;
            responseHeader.PID = requestHeader.PID;
            responseHeader.UID = requestHeader.UID;
            responseHeader.TID = requestHeader.TID;
        }
    }
}