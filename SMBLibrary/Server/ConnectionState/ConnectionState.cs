/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using SMBLibrary.Authentication.GSSAPI;
using SMBLibrary.NetBios;
using Utilities;

namespace SMBLibrary.Server
{
    internal delegate void LogDelegate(Severity severity, string message);

    internal class ConnectionState
    {
        private readonly Socket m_clientSocket;
        private readonly IPEndPoint m_clientEndPoint;
        private readonly NBTConnectionReceiveBuffer m_receiveBuffer;
        private readonly BlockingQueue<SessionPacket> m_sendQueue;
        private readonly DateTime m_creationDT;
        private DateTime m_lastReceiveDT;
        private readonly Reference<DateTime> m_lastSendDTRef; // We must use a reference because the sender thread will keep using the original ConnectionState object
        private readonly LogDelegate LogToServerHandler;
        public SMBDialect Dialect;
        public GSSContext AuthenticationContext;

        public ConnectionState(Socket clientSocket, IPEndPoint clientEndPoint, LogDelegate logToServerHandler)
        {
            m_clientSocket = clientSocket;
            m_clientEndPoint = clientEndPoint;
            m_receiveBuffer = new NBTConnectionReceiveBuffer();
            m_sendQueue = new BlockingQueue<SessionPacket>();
            m_creationDT = DateTime.UtcNow;
            m_lastReceiveDT = DateTime.UtcNow;
            m_lastSendDTRef = DateTime.UtcNow;
            LogToServerHandler = logToServerHandler;
            Dialect = SMBDialect.NotSet;
        }

        public ConnectionState(ConnectionState state)
        {
            m_clientSocket = state.ClientSocket;
            m_clientEndPoint = state.ClientEndPoint;
            m_receiveBuffer = state.ReceiveBuffer;
            m_sendQueue = state.SendQueue;
            m_creationDT = state.CreationDT;
            m_lastReceiveDT = state.LastReceiveDT;
            m_lastSendDTRef = state.LastSendDTRef;
            LogToServerHandler = state.LogToServerHandler;
            Dialect = state.Dialect;
        }

        /// <summary>
        /// Free all resources used by the active sessions in this connection
        /// </summary>
        public virtual void CloseSessions()
        {
        }

        public virtual List<SessionInformation> GetSessionsInformation()
        {
            return new List<SessionInformation>();
        }

        public void LogToServer(Severity severity, string message)
        {
            message = $"[{ConnectionIdentifier}] {message}";
            LogToServerHandler?.Invoke(severity, message);
        }

        public void LogToServer(Severity severity, string message, params object[] args)
        {
            LogToServer(severity, string.Format(message, args));
        }

        public Socket ClientSocket => m_clientSocket;

        public IPEndPoint ClientEndPoint => m_clientEndPoint;

        public NBTConnectionReceiveBuffer ReceiveBuffer => m_receiveBuffer;

        public BlockingQueue<SessionPacket> SendQueue => m_sendQueue;

        public DateTime CreationDT => m_creationDT;

        public DateTime LastReceiveDT => m_lastReceiveDT;

        public DateTime LastSendDT => LastSendDTRef.Value;

        internal Reference<DateTime> LastSendDTRef => m_lastSendDTRef;

        public void UpdateLastReceiveDT()
        {
            m_lastReceiveDT = DateTime.UtcNow;
        }

        public void UpdateLastSendDT()
        {
            m_lastSendDTRef.Value = DateTime.UtcNow;
        }

        public string ConnectionIdentifier
        {
            get
            {
                if (ClientEndPoint != null)
                {
                    return ClientEndPoint.Address + ":" + ClientEndPoint.Port;
                }
                return string.Empty;
            }
        }
    }
}