/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Collections.Generic;
using SMBLibrary.Services;

namespace SMBLibrary.Server
{
    public class NamedPipeShare : ISMBShare
    {
        // A pipe share, as defined by the SMB Protocol, MUST always have the name "IPC$".
        public const string NamedPipeShareName = "IPC$";

        private readonly NamedPipeStore m_store;

        public NamedPipeShare(List<string> shareList)
        {
            List<RemoteService> services = new List<RemoteService>
            {
                new ServerService(Environment.MachineName, shareList),
                new WorkstationService(Environment.MachineName, Environment.MachineName)
            };
            m_store = new NamedPipeStore(services);
        }

        public string Name => NamedPipeShareName;

        public INTFileStore FileStore => m_store;
    }
}
