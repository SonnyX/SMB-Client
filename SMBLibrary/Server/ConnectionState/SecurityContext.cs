/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Net;
using SMBLibrary.Authentication.GssApi;

namespace SMBLibrary
{
    public class SecurityContext
    {
        private readonly string m_userName;
        private readonly string m_machineName;
        private readonly IPEndPoint m_clientEndPoint;
        public GssContext AuthenticationContext;
        public object AccessToken;

        public SecurityContext(string userName, string machineName, IPEndPoint clientEndPoint, GssContext authenticationContext, object accessToken)
        {
            m_userName = userName;
            m_machineName = machineName;
            m_clientEndPoint = clientEndPoint;
            AuthenticationContext = authenticationContext;
            AccessToken = accessToken;
        }

        public string UserName => m_userName;

        public string MachineName => m_machineName;

        public IPEndPoint ClientEndPoint => m_clientEndPoint;
    }
}