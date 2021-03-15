using System.Threading;
using Xunit;

namespace SMBLibrary.Tests
{
    public abstract class NTFileStoreTests
    {
        private readonly INtFileStore m_fileStore;
        private readonly string TestDirName = "Dir";

        private NTStatus? m_notifyChangeStatus;

        public NTFileStoreTests(INtFileStore fileStore)
        {
            m_fileStore = fileStore;
            m_fileStore.CreateFile(out NtHandle handle, out _, TestDirName, AccessMask.GENERIC_ALL, FileAttributes.Directory, ShareAccess.Read, CreateDisposition.FILE_OPEN_IF, CreateOptions.FILE_DIRECTORY_FILE, null);
            m_fileStore.CloseFile(handle);
        }

        [Fact]
        public void TestCancel()
        {
            m_fileStore.CreateFile(out NtHandle handle, out FileStatus fileStatus, TestDirName, AccessMask.GENERIC_ALL, FileAttributes.Directory, ShareAccess.Read, CreateDisposition.FILE_OPEN, CreateOptions.FILE_DIRECTORY_FILE, null);

            m_fileStore.NotifyChange(out object ioRequest, handle, NotifyChangeFilter.FileName | NotifyChangeFilter.LastWrite | NotifyChangeFilter.DirName, false, 8192, OnNotifyChangeCompleted, null);
            //Assert.True(status == NTStatus.STATUS_PENDING);

            Thread.Sleep(1);
            m_fileStore.Cancel(ioRequest);
            m_fileStore.CloseFile(handle);
            while (m_notifyChangeStatus == null)
            {
                Thread.Sleep(1);
            }
            Assert.True(m_notifyChangeStatus.Value == NTStatus.STATUS_CANCELLED);
        }

        private void OnNotifyChangeCompleted(NTStatus status, byte[] buffer, object context)
        {
            m_notifyChangeStatus = status;
        }
    }
}