/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.IO;

namespace SMBLibrary.Server
{
    internal class OpenFileObject
    {
        private readonly uint m_treeID;
        private readonly string m_shareName;
        private string m_path;
        private readonly object m_handle;
        private readonly FileAccess m_fileAccess;
        private readonly DateTime m_openedDT;

        public OpenFileObject(uint treeID, string shareName, string path, object handle, FileAccess fileAccess)
        {
            m_treeID = treeID;
            m_shareName = shareName;
            m_path = path;
            m_handle = handle;
            m_fileAccess = fileAccess;
            m_openedDT = DateTime.UtcNow;
        }

        public uint TreeID => m_treeID;

        public string ShareName => m_shareName;

        public string Path
        {
            get => m_path;
            set => m_path = value;
        }

        public object Handle => m_handle;

        public FileAccess FileAccess => m_fileAccess;

        public DateTime OpenedDT => m_openedDT;
    }
}
