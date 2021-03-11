/* Copyright (C) 2017-2021 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using SMBLibrary.NetBios;
using SMBLibrary.SMB2;
using Utilities;

namespace SMBLibrary.Client
{
    public sealed class Smb2Client : ISmbClient
    {
        public static readonly int NetBiosOverTCPPort = 139;
        public static readonly int DirectTCPPort = 445;

        public static readonly uint ClientMaxTransactSize = 1048576;
        public static readonly uint ClientMaxReadSize = 1048576;
        public static readonly uint ClientMaxWriteSize = 1048576;
        private static readonly ushort DesiredCredits = 16;

        private SMBTransportType m_transport;
        private bool m_isConnected;
        private bool m_isLoggedIn;
        private Socket? m_clientSocket;

        private readonly object m_incomingQueueLock = new object();
        private readonly List<SMB2Command> m_incomingQueue = new List<SMB2Command>();
        private readonly EventWaitHandle m_incomingQueueEventHandle = new EventWaitHandle(false, EventResetMode.AutoReset);

        private SessionPacket? m_sessionResponsePacket;
        private readonly EventWaitHandle m_sessionResponseEventHandle = new EventWaitHandle(false, EventResetMode.AutoReset);

        private uint m_messageID;
        private SMB2Dialect? m_dialect;
        private bool m_signingRequired;
        private byte[] m_signingKey;
        private bool m_encryptSessionData;
        private byte[] m_encryptionKey;
        private byte[] m_decryptionKey;
        private uint m_maxTransactSize;
        private uint m_maxReadSize;
        private uint m_maxWriteSize;
        private ulong m_sessionID;
        private byte[] m_securityBlob;
        private byte[]? m_sessionKey;
        private ushort m_availableCredits = 1;

        public bool IsConnected => m_isConnected && (m_clientSocket?.Connected ?? false);
        public bool IsLoggedIn => m_isLoggedIn && IsConnected;

        public bool Connect(IPAddress serverAddress, SMBTransportType transport)
        {
            // Sometimes underline socket is disconnected, but m_isConnected flag is still true.
            // This cause the caller try to reuse the client and fail on all calls.
            if (m_clientSocket is { Connected: false })
            {
                m_isConnected = false;
                m_isLoggedIn = false;
            }

            m_transport = transport;
            if (m_isConnected)
                return m_isConnected;

            int port = transport == SMBTransportType.NetBiosOverTcp ? NetBiosOverTCPPort : DirectTCPPort;
            ConnectSocket(serverAddress, port);

            if (transport == SMBTransportType.NetBiosOverTcp)
            {
                SessionRequestPacket sessionRequest = new SessionRequestPacket
                {
                    CalledName = NetBiosUtils.GetMSNetBiosName("*SMBSERVER", NetBiosSuffix.FileServiceService),
                    CallingName = NetBiosUtils.GetMSNetBiosName(Environment.MachineName, NetBiosSuffix.WorkstationService)
                };
                SendPacket(m_clientSocket!, sessionRequest);

                SessionPacket sessionResponsePacket = WaitForSessionResponsePacket();
                if (!(sessionResponsePacket is PositiveSessionResponsePacket))
                {
                    ConnectSocket(serverAddress, port);

                    NameServiceClient nameServiceClient = new NameServiceClient(serverAddress);
                    string? serverName = nameServiceClient.GetServerName();
                    if (serverName == null)
                        return false;

                    sessionRequest.CalledName = serverName;
                    SendPacket(m_clientSocket!, sessionRequest);

                    sessionResponsePacket = WaitForSessionResponsePacket();
                    if (!(sessionResponsePacket is PositiveSessionResponsePacket))
                        return false;
                }
            }

            if (m_dialect == null && !NegotiateDialect())
            {
                m_clientSocket?.Close();
            }
            else
            {
                m_isConnected = true;
            }
            return m_isConnected;
        }

        private void ConnectSocket(IPAddress serverAddress, int port)
        {
            m_clientSocket?.Disconnect(false);
            m_clientSocket?.Shutdown(SocketShutdown.Both);
            m_clientSocket?.Dispose();
            m_clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            m_clientSocket.Connect(serverAddress, port);

            ConnectionState state = new ConnectionState(m_clientSocket);
            NBTConnectionReceiveBuffer buffer = state.ReceiveBuffer;
            m_clientSocket.BeginReceive(buffer.Buffer, buffer.WriteOffset, buffer.AvailableLength, SocketFlags.None, OnClientSocketReceive, state);
        }

        public void Disconnect()
        {
            m_isConnected = false;

            if (!m_clientSocket?.Connected ?? true)
                return;
            m_clientSocket?.Shutdown(SocketShutdown.Both);
            m_clientSocket?.Dispose();
            m_clientSocket = null;
        }

        private bool NegotiateDialect()
        {
            NegotiateRequest request = new NegotiateRequest
            {
                SecurityMode = SecurityMode.SigningEnabled,
                Capabilities = Capabilities.Encryption,
                ClientGuid = Guid.NewGuid(),
                ClientStartTime = DateTime.Now
            };
            request.Dialects.Add(SMB2Dialect.SMB202);
            request.Dialects.Add(SMB2Dialect.SMB210);
            request.Dialects.Add(SMB2Dialect.SMB300);

            SendCommand(request);
            SMB2Command? command = WaitForCommand(request.MessageID);
            if (!(command is NegotiateResponse response) || response.Header.Status != NTStatus.STATUS_SUCCESS)
                return false;

            m_dialect = response.DialectRevision;
            m_signingRequired = (response.SecurityMode & SecurityMode.SigningRequired) > 0;
            m_maxTransactSize = Math.Min(response.MaxTransactSize, ClientMaxTransactSize);
            m_maxReadSize = Math.Min(response.MaxReadSize, ClientMaxReadSize);
            m_maxWriteSize = Math.Min(response.MaxWriteSize, ClientMaxWriteSize);
            m_securityBlob = response.SecurityBuffer;
            return true;
        }

        public void Login(string domainName, string userName, string password) => Login(domainName, userName, password, AuthenticationMethod.NtlmV2);

        public void Login(string domainName, string userName, string password, AuthenticationMethod authenticationMethod)
        {
            if (!IsConnected)
                throw new InvalidOperationException("A connection must be successfully established before attempting login");

            byte[]? negotiateMessage = NtlmAuthenticationHelper.GetNegotiateMessage(m_securityBlob, domainName, authenticationMethod);
            if (negotiateMessage == null)
                throw new NtStatusException(NTStatus.SEC_E_INVALID_TOKEN);

            SessionSetupRequest request = new SessionSetupRequest
            {
                SecurityMode = SecurityMode.SigningEnabled,
                SecurityBuffer = negotiateMessage
            };
            SendCommand(request);

            SessionSetupResponse sessionSetupResponse = (SessionSetupResponse) WaitForCommand(request.MessageID);
            sessionSetupResponse.MoreProcessingRequiredElseThrow();

            byte[]? authenticateMessage = NtlmAuthenticationHelper.GetAuthenticateMessage(sessionSetupResponse.SecurityBuffer, domainName, userName, password, authenticationMethod, out m_sessionKey);
            if (authenticateMessage == null)
            {
                throw new NtStatusException(NTStatus.SEC_E_INVALID_TOKEN);
            }

            m_sessionID = sessionSetupResponse.Header.SessionID;
            request = new SessionSetupRequest
            {
                SecurityMode = SecurityMode.SigningEnabled,
                SecurityBuffer = authenticateMessage
            };
            SendCommand(request);
            SMB2Command response = WaitForCommand(request.MessageID);
            response.IsSuccessElseThrow();
            
            m_isLoggedIn = true;

            m_signingKey = SMB2Cryptography.GenerateSigningKey(m_sessionKey, m_dialect.Value, null);
            if (m_dialect != SMB2Dialect.SMB300)
            {
                response.IsSuccessElseThrow();
                return;
            }

            m_encryptSessionData = (((SessionSetupResponse)response).SessionFlags & SessionFlags.EncryptData) > 0;
            m_encryptionKey = SMB2Cryptography.GenerateClientEncryptionKey(m_sessionKey, SMB2Dialect.SMB300, null);
            m_decryptionKey = SMB2Cryptography.GenerateClientDecryptionKey(m_sessionKey, SMB2Dialect.SMB300, null);
            response.IsSuccessElseThrow();
        }

        public void Logoff()
        {
            if (!IsConnected)
            {
                throw new InvalidOperationException("A login session must be successfully established before attempting logoff");
            }

            LogoffRequest request = new LogoffRequest();
            SendCommand(request);

            SMB2Command? response = WaitForCommand(request.MessageID);
            if (response == null)
                throw new NtStatusException(NTStatus.STATUS_INVALID_SMB);

            m_isLoggedIn = (response.Header.Status != NTStatus.STATUS_SUCCESS);
            response.IsSuccessElseThrow();
        }

        public List<string> ListShares()
        {
            if (!IsConnected)
                throw new InvalidOperationException("A session must be successfully established before retrieving share list");

            if (!m_isLoggedIn)
                throw new InvalidOperationException("A login session must be successfully established before retrieving share list");

            ISmbFileStore namedPipeShare = TreeConnect("IPC$");
            List<string> shares = ServerServiceHelper.ListShares(namedPipeShare, Services.ShareType.DiskDrive);
            namedPipeShare.Disconnect();
            return shares;
        }

        public ISmbFileStore TreeConnect(string shareName)
        {
            if (!IsConnected)
                throw new InvalidOperationException("A session must be successfully established before connecting to a share");

            if (!m_isLoggedIn)
                throw new InvalidOperationException("A login session must be successfully established before connecting to a share");

            IPAddress serverIpAddress = ((IPEndPoint)m_clientSocket.RemoteEndPoint).Address;
            string sharePath = $@"\\{serverIpAddress}\{shareName}";
            TreeConnectRequest request = new TreeConnectRequest
            {
                Path = sharePath
            };
            SendCommand(request);
            TreeConnectResponse response = (TreeConnectResponse)WaitForCommand(request.MessageID);
            response.IsSuccessElseThrow();
            bool encryptShareData = (response.ShareFlags & ShareFlags.EncryptData) > 0;
            return new Smb2FileStore(this, response.Header.TreeID, m_encryptSessionData || encryptShareData);
        }

        private void OnClientSocketReceive(IAsyncResult ar)
        {
            if (!ar.IsCompleted && !ar.CompletedSynchronously)
            {
                throw new ObjectDisposedException("Could this be what's happening?");
            }

            ConnectionState state = (ConnectionState)ar.AsyncState;
            Socket clientSocket = state.ClientSocket;

            if (!clientSocket.Connected)
            {
                m_isConnected = false;
                return;
            }

            int numberOfBytesReceived;
            try
            {
                numberOfBytesReceived = clientSocket.EndReceive(ar);
            }
            catch (ArgumentException) // The IAsyncResult object was not returned from the corresponding synchronous method on this class.
            {
                Log("[ReceiveCallback] EndReceive ArgumentException: The IAsyncResult object was not returned from the corresponding synchronous method on this class");
                m_isConnected = false;
                return;
            }
            catch (ObjectDisposedException)
            {
                Log("[ReceiveCallback] EndReceive ObjectDisposedException");
                return;
            }
            catch (SocketException ex)
            {
                Log("[ReceiveCallback] EndReceive SocketException: " + ex.Message);
                m_isConnected = false;
                return;
            }

            if (numberOfBytesReceived == 0)
            {
                if (!m_clientSocket?.Connected ?? true)
                    m_isConnected = false;
            }
            else
            {
                NBTConnectionReceiveBuffer buffer = state.ReceiveBuffer;
                buffer.SetNumberOfBytesReceived(numberOfBytesReceived);
                ProcessConnectionBuffer(state);

                try
                {
                    clientSocket.BeginReceive(buffer.Buffer, buffer.WriteOffset, buffer.AvailableLength, SocketFlags.None, OnClientSocketReceive, state);
                }
                catch (ObjectDisposedException)
                {
                    m_isConnected = false;
                    Log("[ReceiveCallback] BeginReceive ObjectDisposedException");
                }
                catch (SocketException ex)
                {
                    m_isConnected = false;
                    Log("[ReceiveCallback] BeginReceive SocketException: " + ex.Message);
                }
            }
        }

        private void ProcessConnectionBuffer(ConnectionState state)
        {
            NBTConnectionReceiveBuffer receiveBuffer = state.ReceiveBuffer;
            while (receiveBuffer.HasCompletePacket())
            {
                SessionPacket packet;
                try
                {
                    packet = receiveBuffer.DequeuePacket();
                }
                catch (Exception)
                {
                    state.ClientSocket.Close();
                    m_isConnected = false;
                    break;
                }

                ProcessPacket(packet, state);
            }
        }

        private void ProcessPacket(SessionPacket packet, ConnectionState state)
        {
            if (packet is SessionMessagePacket)
            {
                byte[] messageBytes;
                if (m_dialect == SMB2Dialect.SMB300 && SMB2TransformHeader.IsTransformHeader(packet.Trailer, 0))
                {
                    SMB2TransformHeader transformHeader = new SMB2TransformHeader(packet.Trailer, 0);
                    byte[] encryptedMessage = ByteReader.ReadBytes(packet.Trailer, SMB2TransformHeader.Length, (int)transformHeader.OriginalMessageSize);
                    messageBytes = SMB2Cryptography.DecryptMessage(m_decryptionKey, transformHeader, encryptedMessage);
                }
                else
                {
                    messageBytes = packet.Trailer;
                }

                SMB2Command command;
                try
                {
                    command = SMB2Command.ReadResponse(messageBytes, 0);
                }
                catch (Exception ex)
                {
                    Log("Invalid SMB2 response: " + ex.Message);
                    state.ClientSocket.Close();
                    return;
                }

                m_availableCredits += command.Header.Credits;

                if (m_transport == SMBTransportType.DirectTcpTransport && command is NegotiateResponse negotiateResponse)
                {
                    if ((negotiateResponse.Capabilities & Capabilities.LargeMTU) > 0)
                    {
                        // [MS-SMB2] 3.2.5.1 Receiving Any Message - If the message size received exceeds Connection.MaxTransactSize, the client MUST disconnect the connection.
                        // Note: Windows clients do not enforce the MaxTransactSize value, we add 256 bytes.
                        int maxPacketSize = SessionPacket.HeaderLength + (int)Math.Min(negotiateResponse.MaxTransactSize, ClientMaxTransactSize) + 256;
                        if (maxPacketSize > state.ReceiveBuffer.Buffer.Length)
                        {
                            state.ReceiveBuffer.IncreaseBufferSize(maxPacketSize);
                        }
                    }
                }

                // [MS-SMB2] 3.2.5.1.2 - If the MessageId is 0xFFFFFFFFFFFFFFFF, this is not a reply to a previous request,
                // and the client MUST NOT attempt to locate the request, but instead process it as follows:
                // If the command field in the SMB2 header is SMB2 OPLOCK_BREAK, it MUST be processed as specified in 3.2.5.19.
                // Otherwise, the response MUST be discarded as invalid.
                if (command.Header.MessageID == 0xFFFFFFFFFFFFFFFF && command.Header.Command != SMB2CommandName.OplockBreak)
                    return;

                lock (m_incomingQueueLock)
                {
                    m_incomingQueue.Add(command);
                    m_incomingQueueEventHandle.Set();
                }
            }
            else if ((packet is PositiveSessionResponsePacket || packet is NegativeSessionResponsePacket) && m_transport == SMBTransportType.NetBiosOverTcp)
            {
                m_sessionResponsePacket = packet;
                m_sessionResponseEventHandle.Set();
            }
            else if (packet is SessionKeepAlivePacket && m_transport == SMBTransportType.NetBiosOverTcp)
            {
                // [RFC 1001] NetBIOS session keep alives do not require a response from the NetBIOS peer
            }
            else
            {
                Log("Inappropriate NetBIOS session packet");
                state.ClientSocket.Close();
            }
        }

        internal SMB2Command WaitForCommand(ulong messageID)
        {
            const int timeOut = 10000;
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();
            while (stopwatch.ElapsedMilliseconds < timeOut)
            {
                lock (m_incomingQueueLock)
                {
                    for (int index = 0; index < m_incomingQueue.Count; index++)
                    {
                        SMB2Command command = m_incomingQueue[index];

                        if (command.Header.MessageID == messageID)
                        {
                            m_incomingQueue.RemoveAt(index);
                            if (command.Header.IsAsync && command.Header.Status == NTStatus.STATUS_PENDING)
                            {
                                index--;
                                continue;
                            }
                            return command;
                        }
                    }
                }
                m_incomingQueueEventHandle.WaitOne(100);
            }

            throw new TimeoutException($"WaitForCommand: {messageID} timed out ({timeOut} ms)");
        }

        private SessionPacket WaitForSessionResponsePacket()
        {
            const int timeOut = 5000;
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();
            while (stopwatch.ElapsedMilliseconds < timeOut)
            {
                if (m_sessionResponsePacket != null)
                {
                    SessionPacket result = m_sessionResponsePacket;
                    m_sessionResponsePacket = null;
                    return result;
                }

                m_sessionResponseEventHandle.WaitOne(100);
            }

            throw new TimeoutException($"WaitForSessionResponsePacket: timed out ({timeOut} ms)");
        }

        private void Log(string message)
        {
            Debug.Print(message);
        }

        private void SendCommand(SMB2Command request)
        {
            SendCommand(request, m_encryptSessionData);
        }

        internal void SendCommand(SMB2Command request, bool encryptData)
        {
            if (m_dialect == SMB2Dialect.SMB202 || m_transport == SMBTransportType.NetBiosOverTcp)
            {
                request.Header.CreditCharge = 0;
                request.Header.Credits = 1;
                m_availableCredits -= 1;
            }
            else
            {
                if (request.Header.CreditCharge == 0)
                {
                    request.Header.CreditCharge = 1;
                }

                if (m_availableCredits < request.Header.CreditCharge)
                {
                    throw new Exception("Not enough credits");
                }

                m_availableCredits -= request.Header.CreditCharge;

                if (m_availableCredits < DesiredCredits)
                {
                    request.Header.Credits += (ushort)(DesiredCredits - m_availableCredits);
                }
            }

            request.Header.MessageID = m_messageID;
            request.Header.SessionID = m_sessionID;
            // [MS-SMB2] If the client encrypts the message [..] then the client MUST set the Signature field of the SMB2 header to zero
            if (m_signingRequired && !encryptData)
            {
                request.Header.IsSigned = (m_sessionID != 0 && ((request.CommandName == SMB2CommandName.TreeConnect || request.Header.TreeID != 0) || (m_dialect == SMB2Dialect.SMB300 && request.CommandName == SMB2CommandName.Logoff)));
                if (request.Header.IsSigned)
                {
                    request.Header.Signature = new byte[16]; // Request could be reused
                    byte[] buffer = request.GetBytes();
                    byte[] signature = SMB2Cryptography.CalculateSignature(m_signingKey, m_dialect.Value, buffer, 0, buffer.Length);
                    // [MS-SMB2] The first 16 bytes of the hash MUST be copied into the 16-byte signature field of the SMB2 Header.
                    request.Header.Signature = ByteReader.ReadBytes(signature, 0, 16);
                }
            }
            SendCommand(m_clientSocket!, request, encryptData ? m_encryptionKey : null);
            if (m_dialect == SMB2Dialect.SMB202 || m_transport == SMBTransportType.NetBiosOverTcp)
            {
                m_messageID++;
            }
            else
            {
                m_messageID += request.Header.CreditCharge;
            }
        }

        public uint MaxTransactSize => m_maxTransactSize;

        public uint MaxReadSize => m_maxReadSize;

        public uint MaxWriteSize => m_maxWriteSize;

        private static void SendCommand(Socket socket, SMB2Command request, byte[]? encryptionKey)
        {
            SessionMessagePacket packet = new SessionMessagePacket();
            if (encryptionKey != null)
            {
                byte[] requestBytes = request.GetBytes();
                packet.Trailer = SMB2Cryptography.TransformMessage(encryptionKey, requestBytes, request.Header.SessionID);
            }
            else
            {
                packet.Trailer = request.GetBytes();
            }
            SendPacket(socket, packet);
        }

        private static void SendPacket(Socket socket, SessionPacket packet)
        {
            byte[] packetBytes = packet.GetBytes();
            int bytesSend = socket.Send(packetBytes);
            if (bytesSend != packetBytes.Length)
                throw new Exception("Failed to send all bytes!");
        }

        public void Dispose()
        {
            m_clientSocket?.Dispose();
            m_incomingQueueEventHandle.Dispose();
            m_sessionResponseEventHandle.Dispose();
        }
    }
}