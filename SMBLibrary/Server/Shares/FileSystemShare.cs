/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.IO;

namespace SMBLibrary.Server
{
    public class FileSystemShare : ISMBShare
    {
        private readonly string m_name;
        private readonly INTFileStore m_fileSystem;
        private readonly CachingPolicy m_cachingPolicy;

        public event EventHandler<AccessRequestArgs> AccessRequested;

        public FileSystemShare(string shareName, INTFileStore fileSystem) : this(shareName, fileSystem, CachingPolicy.ManualCaching)
        {
        }

        public FileSystemShare(string shareName, INTFileStore fileSystem, CachingPolicy cachingPolicy)
        {
            m_name = shareName;
            m_fileSystem = fileSystem;
            m_cachingPolicy = cachingPolicy;
        }

        public bool HasReadAccess(SecurityContext securityContext, string path)
        {
            return HasAccess(securityContext, path, FileAccess.Read);
        }

        public bool HasWriteAccess(SecurityContext securityContext, string path)
        {
            return HasAccess(securityContext, path, FileAccess.Write);
        }

        public bool HasAccess(SecurityContext securityContext, string path, FileAccess requestedAccess)
        {
            // To be thread-safe we must capture the delegate reference first
            EventHandler<AccessRequestArgs> handler = AccessRequested;
            if (handler != null)
            {
                AccessRequestArgs args = new AccessRequestArgs(securityContext.UserName, path, requestedAccess, securityContext.MachineName, securityContext.ClientEndPoint);
                handler(this, args);
                return args.Allow;
            }
            return true;
        }

        public string Name => m_name;

        public INTFileStore FileStore => m_fileSystem;

        public CachingPolicy CachingPolicy => m_cachingPolicy;
    }
}
