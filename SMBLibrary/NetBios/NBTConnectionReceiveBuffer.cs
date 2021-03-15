/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.IO;

namespace SMBLibrary.NetBios
{
    public class NBTConnectionReceiveBuffer
    {
        private byte[] m_buffer;
        private int m_readOffset;
        private int m_bytesInBuffer;
        private int? m_packetLength;

        public NBTConnectionReceiveBuffer() : this(SessionPacket.MaxSessionPacketLength)
        {
        }

        /// <param name="bufferLength">Must be large enough to hold the largest possible NBT packet</param>
        public NBTConnectionReceiveBuffer(int bufferLength)
        {
            if (bufferLength < SessionPacket.MaxSessionPacketLength)
            {
                throw new ArgumentException("bufferLength must be large enough to hold the largest possible NBT packet");
            }
            m_buffer = new byte[bufferLength];
        }

        public void IncreaseBufferSize(int bufferLength)
        {
            byte[] buffer = new byte[bufferLength];
            lock (m_buffer)
            {
                if (m_bytesInBuffer > 0)
                {
                    Array.Copy(m_buffer, m_readOffset, buffer, 0, m_bytesInBuffer);
                    m_readOffset = 0;
                }

                m_buffer = buffer;
            }
        }

        public void SetNumberOfBytesReceived(int numberOfBytesReceived)
        {
            m_bytesInBuffer += numberOfBytesReceived;
        }

        public bool HasCompletePacket()
        {
            if (m_bytesInBuffer < 4)
                return false;

            m_packetLength ??= SessionPacket.GetSessionPacketLength(m_buffer, m_readOffset);
            return m_bytesInBuffer >= m_packetLength.Value;
        }

        /// <summary>
        /// HasCompletePacket must be called and return true before calling DequeuePacket
        /// </summary>
        /// <exception cref="InvalidDataException"></exception>
        public SessionPacket DequeuePacket()
        {
            SessionPacket packet;
            try
            {
                packet = SessionPacket.GetSessionPacket(m_buffer, m_readOffset);
            }
            catch (IndexOutOfRangeException ex)
            {
                throw new InvalidDataException("Invalid NetBIOS session packet", ex);
            }
            RemovePacketBytes();
            return packet;
        }

        private void RemovePacketBytes()
        {
            m_bytesInBuffer -= m_packetLength ?? 0;
            if (m_bytesInBuffer == 0)
            {
                m_readOffset = 0;
                m_packetLength = null;
            }
            else
            {
                m_readOffset += m_packetLength ?? 0;
                m_packetLength = null;
                if (HasCompletePacket())
                    return;
                Array.Copy(m_buffer, m_readOffset, m_buffer, 0, m_bytesInBuffer);
                m_readOffset = 0;
            }
        }

        public byte[] Buffer => m_buffer;

        public int WriteOffset => m_readOffset + m_bytesInBuffer;

        public int AvailableLength => m_buffer.Length - (m_readOffset + m_bytesInBuffer);
    }
}
