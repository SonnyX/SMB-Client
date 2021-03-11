/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using System.Net;

namespace SMBLibrary.Client
{
    public interface ISmbClient : IDisposable
    {
        bool Connect(IPAddress serverAddress, SMBTransportType transport);

        void Disconnect();

        void Login(string domainName, string userName, string password);

        void Login(string domainName, string userName, string password, AuthenticationMethod authenticationMethod);

        void Logoff();

        List<string> ListShares();

        ISmbFileStore TreeConnect(string shareName);

        bool IsConnected { get; }
        bool IsLoggedIn { get; }

        uint MaxReadSize { get; }

        uint MaxWriteSize { get; }
    }
}