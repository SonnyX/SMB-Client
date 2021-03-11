/* Copyright (C) 2017-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using System.IO;
using Utilities;

namespace SMBLibrary.SMB2
{
    public abstract class SMB2Command
    {
        public SMB2Header Header;

        public SMB2Command(SMB2CommandName commandName)
        {
            Header = new SMB2Header(commandName);
        }

        public SMB2Command(byte[] buffer, int offset)
        {
            Header = new SMB2Header(buffer, offset);
        }

        public void WriteBytes(byte[] buffer, int offset)
        {
            Header.WriteBytes(buffer, offset);
            WriteCommandBytes(buffer, offset + SMB2Header.Length);
        }

        public abstract void WriteCommandBytes(byte[] buffer, int offset);

        public byte[] GetBytes()
        {
            byte[] buffer = new byte[Length];
            WriteBytes(buffer, 0);
            return buffer;
        }

        public SMB2CommandName CommandName => Header.Command;

        public int Length => SMB2Header.Length + CommandLength;

        public abstract int CommandLength
        {
            get;
        }

        public static SMB2Command ReadRequest(byte[] buffer, int offset)
        {
            SMB2CommandName commandName = (SMB2CommandName)LittleEndianConverter.ToUInt16(buffer, offset + 12);
            return commandName switch
            {
                SMB2CommandName.Negotiate => new NegotiateRequest(buffer, offset),
                SMB2CommandName.SessionSetup => new SessionSetupRequest(buffer, offset),
                SMB2CommandName.Logoff => new LogoffRequest(buffer, offset),
                SMB2CommandName.TreeConnect => new TreeConnectRequest(buffer, offset),
                SMB2CommandName.TreeDisconnect => new TreeDisconnectRequest(buffer, offset),
                SMB2CommandName.Create => new CreateRequest(buffer, offset),
                SMB2CommandName.Close => new CloseRequest(buffer, offset),
                SMB2CommandName.Flush => new FlushRequest(buffer, offset),
                SMB2CommandName.Read => new ReadRequest(buffer, offset),
                SMB2CommandName.Write => new WriteRequest(buffer, offset),
                SMB2CommandName.Lock => new LockRequest(buffer, offset),
                SMB2CommandName.IOCtl => new IOCtlRequest(buffer, offset),
                SMB2CommandName.Cancel => new CancelRequest(buffer, offset),
                SMB2CommandName.Echo => new EchoRequest(buffer, offset),
                SMB2CommandName.QueryDirectory => new QueryDirectoryRequest(buffer, offset),
                SMB2CommandName.ChangeNotify => new ChangeNotifyRequest(buffer, offset),
                SMB2CommandName.QueryInfo => new QueryInfoRequest(buffer, offset),
                SMB2CommandName.SetInfo => new SetInfoRequest(buffer, offset),
                _ => throw new InvalidDataException("Invalid SMB2 command 0x" + ((ushort)commandName).ToString("X4"))
            };
        }

        public static List<SMB2Command> ReadRequestChain(byte[] buffer, int offset)
        {
            List<SMB2Command> result = new List<SMB2Command>();
            SMB2Command command;
            do
            {
                command = ReadRequest(buffer, offset);
                result.Add(command);
                offset += (int)command.Header.NextCommand;
            }
            while (command.Header.NextCommand != 0);
            return result;
        }

        public static byte[] GetCommandChainBytes(List<SMB2Command> commands)
        {
            return GetCommandChainBytes(commands, null, SMB2Dialect.SMB2xx);
        }

        /// <param name="sessionKey">
        /// Message will be signed using this key if (not null and) SMB2_FLAGS_SIGNED is set.
        /// </param>
        /// <param name="dialect">
        /// Used for signature calculation when applicable.
        /// </param>
        public static byte[] GetCommandChainBytes(List<SMB2Command> commands, byte[] signingKey, SMB2Dialect dialect)
        {
            int totalLength = 0;
            for (int index = 0; index < commands.Count; index++)
            {
                // Any subsequent SMB2 header MUST be 8-byte aligned
                int length = commands[index].Length;
                if (index < commands.Count - 1)
                {
                    int paddedLength = (int)Math.Ceiling((double)length / 8) * 8;
                    totalLength += paddedLength;
                }
                else
                {
                    totalLength += length;
                }
            }
            byte[] buffer = new byte[totalLength];
            int offset = 0;
            for (int index = 0; index < commands.Count; index++)
            {
                SMB2Command command = commands[index];
                int commandLength = command.Length;
                int paddedLength;
                if (index < commands.Count - 1)
                {
                    paddedLength = (int)Math.Ceiling((double)commandLength / 8) * 8;
                    command.Header.NextCommand = (uint)paddedLength;
                }
                else
                {
                    paddedLength = commandLength;
                }
                command.WriteBytes(buffer, offset);
                if (command.Header.IsSigned && signingKey != null)
                {
                    // [MS-SMB2] Any padding at the end of the message MUST be used in the hash computation.
                    byte[] signature = SMB2Cryptography.CalculateSignature(signingKey, dialect, buffer, offset, paddedLength);
                    // [MS-SMB2] The first 16 bytes of the hash MUST be copied into the 16-byte signature field of the SMB2 Header.
                    ByteWriter.WriteBytes(buffer, offset + SMB2Header.SignatureOffset, signature, 16);
                }
                offset += paddedLength;
            }
            return buffer;
        }

        public static SMB2Command ReadResponse(byte[] buffer, int offset)
        {
            SMB2CommandName commandName = (SMB2CommandName)LittleEndianConverter.ToUInt16(buffer, offset + 12);
            ushort structureSize = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 0);
            switch (commandName)
            {
                case SMB2CommandName.Negotiate:
                    {
                        if (structureSize == NegotiateResponse.DeclaredSize)
                        {
                            return new NegotiateResponse(buffer, offset);
                        }

                        if (structureSize == ErrorResponse.DeclaredSize)
                        {
                            return new ErrorResponse(buffer, offset);
                        }
                        throw new InvalidDataException();
                    }
                case SMB2CommandName.SessionSetup:
                    {
                        // SESSION_SETUP Response and ERROR Response have the same declared StructureSize of 9.
                        if (structureSize == SessionSetupResponse.DeclaredSize)
                        {
                            NTStatus status = (NTStatus)LittleEndianConverter.ToUInt32(buffer, offset + 8);
                            if (status == NTStatus.STATUS_SUCCESS || status == NTStatus.STATUS_MORE_PROCESSING_REQUIRED)
                            {
                                return new SessionSetupResponse(buffer, offset);
                            }

                            return new ErrorResponse(buffer, offset);
                        }

                        throw new InvalidDataException();
                    }
                case SMB2CommandName.Logoff:
                    {
                        if (structureSize == LogoffResponse.DeclaredSize)
                        {
                            return new LogoffResponse(buffer, offset);
                        }

                        if (structureSize == ErrorResponse.DeclaredSize)
                        {
                            return new ErrorResponse(buffer, offset);
                        }
                        throw new InvalidDataException();
                    }
                case SMB2CommandName.TreeConnect:
                    {
                        if (structureSize == TreeConnectResponse.DeclaredSize)
                        {
                            return new TreeConnectResponse(buffer, offset);
                        }

                        if (structureSize == ErrorResponse.DeclaredSize)
                        {
                            return new ErrorResponse(buffer, offset);
                        }
                        throw new InvalidDataException();
                    }
                case SMB2CommandName.TreeDisconnect:
                    {
                        if (structureSize == TreeDisconnectResponse.DeclaredSize)
                        {
                            return new TreeDisconnectResponse(buffer, offset);
                        }

                        if (structureSize == ErrorResponse.DeclaredSize)
                        {
                            return new ErrorResponse(buffer, offset);
                        }
                        throw new InvalidDataException();
                    }
                case SMB2CommandName.Create:
                    {
                        if (structureSize == CreateResponse.DeclaredSize)
                        {
                            return new CreateResponse(buffer, offset);
                        }

                        if (structureSize == ErrorResponse.DeclaredSize)
                        {
                            return new ErrorResponse(buffer, offset);
                        }
                        throw new InvalidDataException();
                    }
                case SMB2CommandName.Close:
                    {
                        if (structureSize == CloseResponse.DeclaredSize)
                        {
                            return new CloseResponse(buffer, offset);
                        }

                        if (structureSize == ErrorResponse.DeclaredSize)
                        {
                            return new ErrorResponse(buffer, offset);
                        }
                        throw new InvalidDataException();
                    }
                case SMB2CommandName.Flush:
                    {
                        if (structureSize == FlushResponse.DeclaredSize)
                        {
                            return new FlushResponse(buffer, offset);
                        }

                        if (structureSize == ErrorResponse.DeclaredSize)
                        {
                            return new ErrorResponse(buffer, offset);
                        }
                        throw new InvalidDataException();
                    }
                case SMB2CommandName.Read:
                    {
                        if (structureSize == SMB2.ReadResponse.DeclaredSize)
                        {
                            return new ReadResponse(buffer, offset);
                        }

                        if (structureSize == ErrorResponse.DeclaredSize)
                        {
                            return new ErrorResponse(buffer, offset);
                        }
                        throw new InvalidDataException();
                    }
                case SMB2CommandName.Write:
                    {
                        if (structureSize == WriteResponse.DeclaredSize)
                        {
                            return new WriteResponse(buffer, offset);
                        }

                        if (structureSize == ErrorResponse.DeclaredSize)
                        {
                            return new ErrorResponse(buffer, offset);
                        }
                        throw new InvalidDataException();
                    }
                case SMB2CommandName.Lock:
                    {
                        if (structureSize == LockResponse.DeclaredSize)
                        {
                            return new LockResponse(buffer, offset);
                        }

                        if (structureSize == ErrorResponse.DeclaredSize)
                        {
                            return new ErrorResponse(buffer, offset);
                        }
                        throw new InvalidDataException();
                    }
                case SMB2CommandName.IOCtl:
                    {
                        if (structureSize == IOCtlResponse.DeclaredSize)
                        {
                            return new IOCtlResponse(buffer, offset);
                        }

                        if (structureSize == ErrorResponse.DeclaredSize)
                        {
                            return new ErrorResponse(buffer, offset);
                        }
                        throw new InvalidDataException();
                    }
                case SMB2CommandName.Cancel:
                    {
                        if (structureSize == ErrorResponse.DeclaredSize)
                        {
                            return new ErrorResponse(buffer, offset);
                        }

                        throw new InvalidDataException();
                    }
                case SMB2CommandName.Echo:
                    {
                        if (structureSize == EchoResponse.DeclaredSize)
                        {
                            return new EchoResponse(buffer, offset);
                        }

                        if (structureSize == ErrorResponse.DeclaredSize)
                        {
                            return new ErrorResponse(buffer, offset);
                        }
                        throw new InvalidDataException();
                    }
                case SMB2CommandName.QueryDirectory:
                    {
                        // QUERY_DIRECTORY Response and ERROR Response have the same declared StructureSize of 9.
                        if (structureSize == QueryDirectoryResponse.DeclaredSize)
                        {
                            NTStatus status = (NTStatus)LittleEndianConverter.ToUInt32(buffer, offset + 8);
                            if (status == NTStatus.STATUS_SUCCESS)
                            {
                                return new QueryDirectoryResponse(buffer, offset);
                            }

                            return new ErrorResponse(buffer, offset);
                        }

                        throw new InvalidDataException();
                    }
                case SMB2CommandName.ChangeNotify:
                    {
                        // CHANGE_NOTIFY Response and ERROR Response have the same declared StructureSize of 9.
                        if (structureSize == ChangeNotifyResponse.DeclaredSize)
                        {
                            NTStatus status = (NTStatus)LittleEndianConverter.ToUInt32(buffer, offset + 8);
                            if (status == NTStatus.STATUS_SUCCESS ||
                                status == NTStatus.STATUS_NOTIFY_CLEANUP ||
                                status == NTStatus.STATUS_NOTIFY_ENUM_DIR)
                            {
                                return new ChangeNotifyResponse(buffer, offset);
                            }

                            return new ErrorResponse(buffer, offset);
                        }

                        throw new InvalidDataException();
                    }
                case SMB2CommandName.QueryInfo:
                    {
                        // QUERY_INFO Response and ERROR Response have the same declared StructureSize of 9.
                        if (structureSize == QueryInfoResponse.DeclaredSize)
                        {
                            NTStatus status = (NTStatus)LittleEndianConverter.ToUInt32(buffer, offset + 8);
                            if (status == NTStatus.STATUS_SUCCESS || status == NTStatus.STATUS_BUFFER_OVERFLOW)
                            {
                                return new QueryInfoResponse(buffer, offset);
                            }

                            return new ErrorResponse(buffer, offset);
                        }

                        throw new InvalidDataException();
                    }
                case SMB2CommandName.SetInfo:
                    {
                        if (structureSize == SetInfoResponse.DeclaredSize)
                        {
                            return new SetInfoResponse(buffer, offset);
                        }

                        if (structureSize == ErrorResponse.DeclaredSize)
                        {
                            return new ErrorResponse(buffer, offset);
                        }
                        throw new InvalidDataException();
                    }
                default:
                    throw new InvalidDataException("Invalid SMB2 command 0x" + ((ushort)commandName).ToString("X4"));
            }
        }

        public static List<SMB2Command> ReadResponseChain(byte[] buffer, int offset)
        {
            List<SMB2Command> result = new List<SMB2Command>();
            SMB2Command command;
            do
            {
                command = ReadResponse(buffer, offset);
                result.Add(command);
                offset += (int)command.Header.NextCommand;
            }
            while (command.Header.NextCommand != 0);
            return result;
        }
    }
}