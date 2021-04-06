/* Copyright (C) 2014-2018 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;

namespace SMBLibrary.Services
{
    /// <summary>
    /// [MS-WKST]
    /// </summary>
    public class WorkstationService : RemoteService
    {
        public const string ServicePipeName = @"wkssvc";
        public static readonly Guid ServiceInterfaceGuid = new Guid("6BFFD098-A112-3610-9833-46C3F87E345A");
        public const int ServiceVersion = 1;

        private readonly uint m_platformID;
        private readonly string? m_computerName;
        private readonly string? m_lanGroup;
        private readonly uint m_verMajor;
        private readonly uint m_verMinor;

        public WorkstationService(string computerName, string lanGroup)
        {
            m_platformID = (uint) PlatformName.NT;
            m_computerName = computerName;
            m_lanGroup = lanGroup;
            m_verMajor = 5;
            m_verMinor = 2;
        }

        public override byte[] GetResponseBytes(ushort opNum, byte[] requestBytes)
        {
            switch ((WorkstationServiceOpName) opNum)
            {
                case WorkstationServiceOpName.NetrWkstaGetInfo:
                    NetrWkstaGetInfoRequest request = new NetrWkstaGetInfoRequest(requestBytes);
                    NetrWkstaGetInfoResponse response = GetNetrWkstaGetInfoResponse(request);
                    return response.GetBytes();
                default:
                    throw new UnsupportedOpNumException();
            }
        }

        public NetrWkstaGetInfoResponse GetNetrWkstaGetInfoResponse(NetrWkstaGetInfoRequest request)
        {
            NetrWkstaGetInfoResponse response = new NetrWkstaGetInfoResponse();
            switch (request.Level)
            {
                case 100:
                {
                    WorkstationInfo100 info = new WorkstationInfo100
                    {
                        PlatformID = m_platformID,
                        ComputerName = {Value = m_computerName},
                        LanGroup = {Value = m_lanGroup},
                        VerMajor = m_verMajor,
                        VerMinor = m_verMinor
                    };
                    response.WkstaInfo = new WorkstationInfo(info);
                    response.Result = Win32Error.ERROR_SUCCESS;
                    return response;
                }
                case 101:
                {
                    WorkstationInfo101 info = new WorkstationInfo101
                    {
                        PlatformID = m_platformID,
                        ComputerName = {Value = m_computerName},
                        LanGroup = {Value = m_lanGroup},
                        VerMajor = m_verMajor,
                        VerMinor = m_verMinor,
                        LanRoot = {Value = m_lanGroup}
                    };
                    response.WkstaInfo = new WorkstationInfo(info);
                    response.Result = Win32Error.ERROR_SUCCESS;
                    return response;
                }
                case 102:
                case 502:
                {
                    response.WkstaInfo = new WorkstationInfo(request.Level);
                    response.Result = Win32Error.ERROR_NOT_SUPPORTED;
                    return response;
                }
                default:
                {
                    response.WkstaInfo = new WorkstationInfo(request.Level);
                    response.Result = Win32Error.ERROR_INVALID_LEVEL;
                    return response;
                }
            }
        }

        public override Guid InterfaceGuid => ServiceInterfaceGuid;

        public override string PipeName => ServicePipeName;
    }
}