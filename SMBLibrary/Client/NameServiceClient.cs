/* Copyright (C) 2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Linq;
using System.Net;
using System.Net.Sockets;
using SMBLibrary.NetBios;

namespace SMBLibrary.Client
{
    public class NameServiceClient
    {
        public static readonly int NetBiosNameServicePort = 137;

        private readonly IPAddress m_serverAddress;

        public NameServiceClient(IPAddress serverAddress)
        {
            m_serverAddress = serverAddress;
        }

        public string? GetServerName()
        {
            NodeStatusRequest request = new NodeStatusRequest {Header = {QDCount = 1}, Question = {Name = "*".PadRight(16, '\0')}};
            NodeStatusResponse response = SendNodeStatusRequest(request);
            return (from entry in response.Names let suffix = NetBiosUtils.GetSuffixFromMSNetBiosName(entry.Key) where suffix == NetBiosSuffix.FileServiceService select entry.Key).FirstOrDefault();
        }

        private NodeStatusResponse SendNodeStatusRequest(NodeStatusRequest request)
        {
            using UdpClient client = new UdpClient();
            IPEndPoint serverEndPoint = new IPEndPoint(m_serverAddress, NetBiosNameServicePort);
            client.Connect(serverEndPoint);

            byte[] requestBytes = request.GetBytes();
            client.Send(requestBytes, requestBytes.Length);
            byte[] responseBytes = client.Receive(ref serverEndPoint);
            return new NodeStatusResponse(responseBytes, 0);
        }
    }
}