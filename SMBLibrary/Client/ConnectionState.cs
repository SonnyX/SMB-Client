/* Copyright (C) 2017-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Net.Sockets;
using SMBLibrary.NetBios;

namespace SMBLibrary.Client
{
    public class ConnectionState
    {
        public ConnectionState(Socket clientSocket)
        {
            ClientSocket = clientSocket;
            ReceiveBuffer = new NBTConnectionReceiveBuffer();
        }

        public Socket ClientSocket { get; }

        public NBTConnectionReceiveBuffer ReceiveBuffer { get; }
    }
}