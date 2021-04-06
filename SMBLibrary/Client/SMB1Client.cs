/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
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
using SMBLibrary.Authentication.NTLM;
using SMBLibrary.NetBios;
using SMBLibrary.Services;
using SMBLibrary.SMB1;
using Utilities;

namespace SMBLibrary.Client
{
    public sealed class Smb1Client : ISmbClient
    {
        private const string NTLanManagerDialect = "NT LM 0.12";
        public static readonly int NetBiosOverTCPPort = 139;
        public static readonly int DirectTCPPort = 445;

        private static readonly ushort ClientMaxBufferSize = 65535; // Valid range: 512 - 65535
        private static readonly ushort ClientMaxMpxCount = 1;

        private SMBTransportType m_transport;
        private bool m_isConnected;
        private bool m_isLoggedIn;
        private Socket? m_clientSocket;
        private bool m_forceExtendedSecurity;
        private bool m_unicode;
        private bool m_largeFiles;
        private bool m_infoLevelPassthrough;
        private bool m_largeRead;
        private bool m_largeWrite;
        private uint m_serverMaxBufferSize;
        private ushort m_maxMpxCount;

        private readonly object m_incomingQueueLock = new object();
        private readonly List<SMB1Message> m_incomingQueue = new List<SMB1Message>();
        private readonly EventWaitHandle m_incomingQueueEventHandle = new EventWaitHandle(false, EventResetMode.AutoReset);

        private SessionPacket? m_sessionResponsePacket;
        private readonly EventWaitHandle m_sessionResponseEventHandle = new EventWaitHandle(false, EventResetMode.AutoReset);

        private ushort m_userID;
        private byte[]? m_serverChallenge;
        private byte[] m_securityBlob;
        private byte[] m_sessionKey;

        public bool IsConnected => m_isConnected && (m_clientSocket?.Connected ?? false);
        public bool IsLoggedIn => m_isLoggedIn;

        public bool Connect(IPAddress serverAddress, SMBTransportType transport)
        {
            return Connect(serverAddress, transport, true);
        }

        private bool Connect(IPAddress serverAddress, SMBTransportType transport, bool forceExtendedSecurity)
        {
            m_transport = transport;
            if (IsConnected)
                return true;

            m_forceExtendedSecurity = forceExtendedSecurity;
            int port = transport == SMBTransportType.NetBiosOverTcp ? NetBiosOverTCPPort : DirectTCPPort;

            ConnectSocket(serverAddress, port);

            if (transport == SMBTransportType.NetBiosOverTcp)
            {
                SessionRequestPacket sessionRequest = new SessionRequestPacket {CalledName = NetBiosUtils.GetMSNetBiosName("*SMBSERVER", NetBiosSuffix.FileServiceService), CallingName = NetBiosUtils.GetMSNetBiosName(Environment.MachineName, NetBiosSuffix.WorkstationService)};
                SendPacket(m_clientSocket!, sessionRequest);

                SessionPacket? sessionResponsePacket = WaitForSessionResponsePacket();
                if (!(sessionResponsePacket is PositiveSessionResponsePacket))
                {
                    m_clientSocket?.Shutdown(SocketShutdown.Both);
                    m_clientSocket?.Dispose();
                    m_clientSocket = null;

                    ConnectSocket(serverAddress, port);

                    NameServiceClient nameServiceClient = new NameServiceClient(serverAddress);
                    string? serverName = nameServiceClient.GetServerName();
                    if (serverName == null)
                    {
                        return false;
                    }

                    sessionRequest.CalledName = serverName;
                    SendPacket(m_clientSocket, sessionRequest);

                    sessionResponsePacket = WaitForSessionResponsePacket();
                    if (!(sessionResponsePacket is PositiveSessionResponsePacket))
                    {
                        return false;
                    }
                }
            }

            bool supportsDialect = NegotiateDialect(m_forceExtendedSecurity);
            if (!supportsDialect)
            {
                m_clientSocket?.Shutdown(SocketShutdown.Both);
                m_clientSocket?.Dispose();
                m_clientSocket = null;
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
            m_clientSocket?.Shutdown(SocketShutdown.Both);
            m_clientSocket?.Dispose();
            m_clientSocket = null;
            m_isConnected = false;
        }

        private bool NegotiateDialect(bool forceExtendedSecurity)
        {
            NegotiateRequest request = new NegotiateRequest();
            request.Dialects.Add(NTLanManagerDialect);

            SendMessage(request);
            SMB1Message reply = WaitForMessage(CommandName.SMB_COM_NEGOTIATE);
            switch (reply.Commands[0])
            {
                case NegotiateResponse negotiateResponse when !forceExtendedSecurity:
                {
                    m_unicode = ((negotiateResponse.Capabilities & Capabilities.Unicode) > 0);
                    m_largeFiles = ((negotiateResponse.Capabilities & Capabilities.LargeFiles) > 0);
                    bool ntSMB = ((negotiateResponse.Capabilities & Capabilities.NTSMB) > 0);
                    bool rpc = ((negotiateResponse.Capabilities & Capabilities.RpcRemoteApi) > 0);
                    bool ntStatusCode = ((negotiateResponse.Capabilities & Capabilities.NTStatusCode) > 0);
                    m_infoLevelPassthrough = ((negotiateResponse.Capabilities & Capabilities.InfoLevelPassthrough) > 0);
                    m_largeRead = ((negotiateResponse.Capabilities & Capabilities.LargeRead) > 0);
                    m_largeWrite = ((negotiateResponse.Capabilities & Capabilities.LargeWrite) > 0);
                    m_serverMaxBufferSize = negotiateResponse.MaxBufferSize;
                    m_maxMpxCount = Math.Min(negotiateResponse.MaxMpxCount, ClientMaxMpxCount);
                    m_serverChallenge = negotiateResponse.Challenge;
                    return ntSMB && rpc && ntStatusCode;
                }
                case NegotiateResponseExtended response:
                {
                    m_unicode = ((response.Capabilities & Capabilities.Unicode) > 0);
                    m_largeFiles = ((response.Capabilities & Capabilities.LargeFiles) > 0);
                    bool ntSMB = ((response.Capabilities & Capabilities.NTSMB) > 0);
                    bool rpc = ((response.Capabilities & Capabilities.RpcRemoteApi) > 0);
                    bool ntStatusCode = ((response.Capabilities & Capabilities.NTStatusCode) > 0);
                    m_infoLevelPassthrough = ((response.Capabilities & Capabilities.InfoLevelPassthrough) > 0);
                    m_largeRead = ((response.Capabilities & Capabilities.LargeRead) > 0);
                    m_largeWrite = ((response.Capabilities & Capabilities.LargeWrite) > 0);
                    m_serverMaxBufferSize = response.MaxBufferSize;
                    m_maxMpxCount = Math.Min(response.MaxMpxCount, ClientMaxMpxCount);
                    m_securityBlob = response.SecurityBlob;
                    return ntSMB && rpc && ntStatusCode;
                }
                default:
                    return false;
            }
        }

        public void Login(string domainName, string userName, string password) => Login(domainName, userName, password, AuthenticationMethod.NtlmV2);

        public void Login(string domainName, string userName, string password, AuthenticationMethod authenticationMethod)
        {
            if (!IsConnected)
                throw new InvalidOperationException("A connection must be successfully established before attempting login");

            Capabilities clientCapabilities = Capabilities.NTSMB | Capabilities.RpcRemoteApi | Capabilities.NTStatusCode | Capabilities.NTFind;
            if (m_unicode)
                clientCapabilities |= Capabilities.Unicode;
            if (m_largeFiles)
                clientCapabilities |= Capabilities.LargeFiles;
            if (m_largeRead)
                clientCapabilities |= Capabilities.LargeRead;

            if (m_serverChallenge != null)
            {
                SessionSetupAndXRequest request = new SessionSetupAndXRequest
                {
                    MaxBufferSize = ClientMaxBufferSize,
                    MaxMpxCount = m_maxMpxCount,
                    Capabilities = clientCapabilities,
                    AccountName = userName,
                    PrimaryDomain = domainName
                };
                byte[] clientChallenge = new byte[8];
                new Random().NextBytes(clientChallenge);
                if (authenticationMethod == AuthenticationMethod.NtlmV1)
                {
                    request.OEMPassword = NtlmCryptography.ComputeLMv1Response(m_serverChallenge, password);
                    request.UnicodePassword = NtlmCryptography.ComputeNTLMv1Response(m_serverChallenge, password);
                }
                else if (authenticationMethod == AuthenticationMethod.NtlmV1ExtendedSessionSecurity)
                {
                    // [MS-CIFS] CIFS does not support Extended Session Security because there is no mechanism in CIFS to negotiate Extended Session Security
                    throw new ArgumentException("SMB Extended Security must be negotiated in order for NtlmV1 Extended Session Security to be used");
                }
                else // NtlmV2
                {
                    // Note: NtlmV2 over non-extended security session setup is not supported under Windows Vista and later which will return STATUS_INVALID_PARAMETER.
                    // https://msdn.microsoft.com/en-us/library/ee441701.aspx
                    // https://msdn.microsoft.com/en-us/library/cc236700.aspx
                    request.OEMPassword = NtlmCryptography.ComputeLMv2Response(m_serverChallenge, clientChallenge, password, userName, domainName);
                    NTLMv2ClientChallenge clientChallengeStructure = new NTLMv2ClientChallenge(DateTime.UtcNow, clientChallenge, AVPairUtils.GetAVPairSequence(domainName, Environment.MachineName));
                    byte[] temp = clientChallengeStructure.GetBytesPadded();
                    byte[] proofStr = NtlmCryptography.ComputeNTLMv2Proof(m_serverChallenge, temp, password, userName, domainName);
                    request.UnicodePassword = ByteUtils.Concatenate(proofStr, temp);
                }

                SendMessage(request);

                SMB1Message reply = WaitForMessage(CommandName.SMB_COM_SESSION_SETUP_ANDX);

                m_isLoggedIn = (reply.Header.Status == NTStatus.STATUS_SUCCESS);
                reply.IsSuccessElseThrow();
            }
            else // m_securityBlob != null
            {
                byte[] negotiateMessage = NtlmAuthenticationHelper.GetNegotiateMessage(m_securityBlob, domainName, authenticationMethod);

                SessionSetupAndXRequestExtended request = new SessionSetupAndXRequestExtended {MaxBufferSize = ClientMaxBufferSize, MaxMpxCount = m_maxMpxCount, Capabilities = clientCapabilities, SecurityBlob = negotiateMessage};
                SendMessage(request);

                SMB1Message reply = WaitForMessage(CommandName.SMB_COM_SESSION_SETUP_ANDX);
                if (reply.Header.Status != NTStatus.STATUS_MORE_PROCESSING_REQUIRED || !(reply.Commands[0] is SessionSetupAndXResponseExtended))
                    throw new NtStatusException(reply.Header.Status);

                SessionSetupAndXResponseExtended response = (SessionSetupAndXResponseExtended) reply.Commands[0];
                byte[]? authenticateMessage = NtlmAuthenticationHelper.GetAuthenticateMessage(response.SecurityBlob, domainName, userName, password, authenticationMethod, out m_sessionKey);
                if (authenticateMessage == null)
                {
                    throw new NtStatusException(NTStatus.SEC_E_INVALID_TOKEN);
                }

                m_userID = reply.Header.UID;
                request = new SessionSetupAndXRequestExtended {MaxBufferSize = ClientMaxBufferSize, MaxMpxCount = m_maxMpxCount, Capabilities = clientCapabilities, SecurityBlob = authenticateMessage};
                SendMessage(request);

                reply = WaitForMessage(CommandName.SMB_COM_SESSION_SETUP_ANDX);

                m_isLoggedIn = (reply.Header.Status == NTStatus.STATUS_SUCCESS);
                reply.IsSuccessElseThrow();
            }
        }

        public void Logoff()
        {
            if (!IsConnected)
                throw new InvalidOperationException("A session must be successfully established before attempting logoff");

            if (!m_isLoggedIn)
                throw new InvalidOperationException("A login session must be successfully established before attempting logoff");

            LogoffAndXRequest request = new LogoffAndXRequest();
            SendMessage(request);

            SMB1Message reply = WaitForMessage(CommandName.SMB_COM_LOGOFF_ANDX);
            if (reply.Header.Status == NTStatus.STATUS_SUCCESS)
                m_isLoggedIn = false;
            reply.IsSuccessElseThrow();
        }

        public List<string> ListShares()
        {
            if (!IsConnected || !m_isLoggedIn)
            {
                throw new InvalidOperationException("A login session must be successfully established before retrieving share list");
            }

            SMB1FileStore namedPipeShare = TreeConnect("IPC$", ServiceName.NamedPipe);

            List<string> shares = ServerServiceHelper.ListShares(namedPipeShare, ShareType.DiskDrive);
            namedPipeShare.Disconnect();
            return shares;
        }

        public ISmbFileStore TreeConnect(string shareName)
        {
            return TreeConnect(shareName, ServiceName.AnyType);
        }

        private SMB1FileStore TreeConnect(string shareName, ServiceName serviceName)
        {
            if (!IsConnected || !m_isLoggedIn)
            {
                throw new InvalidOperationException("A login session must be successfully established before connecting to a share");
            }

            TreeConnectAndXRequest request = new TreeConnectAndXRequest {Path = shareName, Service = serviceName};
            SendMessage(request);
            SMB1Message reply = WaitForMessage(CommandName.SMB_COM_TREE_CONNECT_ANDX);
            reply.IsSuccessElseThrow();
            return new SMB1FileStore(this, reply.Header.TID);
        }

        private void OnClientSocketReceive(IAsyncResult ar)
        {
            ConnectionState state = (ConnectionState) ar.AsyncState;
            Socket clientSocket = state.ClientSocket;

            if (!clientSocket.Connected)
            {
                return;
            }

            int numberOfBytesReceived = 0;
            try
            {
                numberOfBytesReceived = clientSocket.EndReceive(ar);
            }
            catch (ArgumentException) // The IAsyncResult object was not returned from the corresponding synchronous method on this class.
            {
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
                return;
            }

            if (numberOfBytesReceived == 0)
            {
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
                    break;
                }

                ProcessPacket(packet, state);
            }
        }

        private void ProcessPacket(SessionPacket packet, ConnectionState state)
        {
            if (packet is SessionMessagePacket)
            {
                SMB1Message message;
                try
                {
                    message = SMB1Message.GetSMB1Message(packet.Trailer);
                }
                catch (Exception ex)
                {
                    Log("Invalid SMB1 message: " + ex.Message);
                    state.ClientSocket.Close();
                    m_isConnected = false;
                    return;
                }

                // [MS-CIFS] 3.2.5.1 - If the MID value is the reserved value 0xFFFF, the message can be an OpLock break
                // sent by the server. Otherwise, if the PID and MID values of the received message are not found in the
                // Client.Connection.PIDMIDList, the message MUST be discarded.
                if ((message.Header.MID != 0xFFFF || message.Header.Command != CommandName.SMB_COM_LOCKING_ANDX) && (message.Header.PID != 0 || message.Header.MID != 0))
                    return;

                lock (m_incomingQueueLock)
                {
                    m_incomingQueue.Add(message);
                    m_incomingQueueEventHandle?.Set();
                }
            }
            else if ((packet is PositiveSessionResponsePacket || packet is NegativeSessionResponsePacket) && m_transport == SMBTransportType.NetBiosOverTcp)
            {
                m_sessionResponsePacket = packet;
                m_sessionResponseEventHandle?.Set();
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

        internal SMB1Message WaitForMessage(CommandName commandName)
        {
            const int timeOut = 5000;
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();
            while (stopwatch.ElapsedMilliseconds < timeOut)
            {
                lock (m_incomingQueueLock)
                {
                    for (int index = 0; index < m_incomingQueue.Count; index++)
                    {
                        SMB1Message message = m_incomingQueue[index];

                        if (message.Commands[0].CommandName != commandName)
                            continue;

                        m_incomingQueue.RemoveAt(index);
                        return message;
                    }
                }

                m_incomingQueueEventHandle?.WaitOne(100);
            }

            throw new TimeoutException($"WaitForMessage timed out after {timeOut} ms");
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

                m_sessionResponseEventHandle?.WaitOne(100);
            }

            throw new TimeoutException($"WaitForSessionResponsePacket timed out after {timeOut} ms");
        }

        private void Log(string message) => Debug.Print(message);

        private void SendMessage(SMB1Command request) => SendMessage(request, 0);

        internal void SendMessage(SMB1Command request, ushort treeID)
        {
            SMB1Message message = new SMB1Message
            {
                Header = new SMB1Header
                {
                    UnicodeFlag = m_unicode,
                    ExtendedSecurityFlag = m_forceExtendedSecurity,
                    Flags2 = HeaderFlags2.LongNamesAllowed | HeaderFlags2.LongNameUsed | HeaderFlags2.NTStatusCode,
                    UID = m_userID,
                    TID = treeID,
                }
            };

            message.Commands.Add(request);
            SendMessage(m_clientSocket!, message);
        }

        public bool Unicode => m_unicode;

        public bool LargeFiles => m_largeFiles;

        public bool InfoLevelPassthrough => m_infoLevelPassthrough;

        public bool LargeRead => m_largeRead;

        public bool LargeWrite => m_largeWrite;

        public uint ServerMaxBufferSize => m_serverMaxBufferSize;

        public int MaxMpxCount => m_maxMpxCount;

        public uint MaxReadSize => (uint) ClientMaxBufferSize - (SMB1Header.Length + 3 + ReadAndXResponse.ParametersLength);

        public uint MaxWriteSize
        {
            get
            {
                uint result = ServerMaxBufferSize - (SMB1Header.Length + 3 + WriteAndXRequest.ParametersFixedLength + 4);
                if (m_unicode)
                {
                    result--;
                }

                return result;
            }
        }

        public static void SendMessage(Socket socket, SMB1Message message)
        {
            SessionMessagePacket packet = new SessionMessagePacket {Trailer = message.GetBytes()};
            SendPacket(socket, packet);
        }

        public static void SendPacket(Socket socket, SessionPacket packet)
        {
            byte[] packetBytes = packet.GetBytes();
            socket.Send(packetBytes);
        }

        public void Dispose()
        {
            m_clientSocket?.Dispose();
            m_incomingQueueEventHandle.Dispose();
            m_sessionResponseEventHandle.Dispose();
        }
    }
}