/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;

namespace SMBLibrary.Authentication
{
    public class LoginCounter
    {
        public class LoginEntry
        {
            public DateTime LoginWindowStartDt;
            public int NumberOfAttempts;
        }

        private readonly int m_maxLoginAttemptsInWindow;
        private readonly TimeSpan m_loginWindowDuration;
        private readonly Dictionary<string, LoginEntry> m_loginEntries = new Dictionary<string, LoginEntry>();

        public LoginCounter(int maxLoginAttemptsInWindow, TimeSpan loginWindowDuration)
        {
            m_maxLoginAttemptsInWindow = maxLoginAttemptsInWindow;
            m_loginWindowDuration = loginWindowDuration;
        }

        public bool HasRemainingLoginAttempts(string userId)
        {
            return HasRemainingLoginAttempts(userId, false);
        }

        public bool HasRemainingLoginAttempts(string userId, bool incrementCount)
        {
            lock (m_loginEntries)
            {
                if (m_loginEntries.TryGetValue(userId, out LoginEntry entry))
                {
                    if (entry.LoginWindowStartDt.Add(m_loginWindowDuration) >= DateTime.UtcNow)
                    {
                        // Existing login Window
                        if (incrementCount)
                        {
                            entry.NumberOfAttempts++;
                        }
                    }
                    else
                    {
                        // New login Window
                        if (!incrementCount)
                        {
                            return true;
                        }

                        entry.LoginWindowStartDt = DateTime.UtcNow;
                        entry.NumberOfAttempts = 1;
                    }
                }
                else
                {
                    if (!incrementCount)
                    {
                        return true;
                    }

                    entry = new LoginEntry {LoginWindowStartDt = DateTime.UtcNow, NumberOfAttempts = 1};
                    m_loginEntries.Add(userId, entry);
                }

                return (entry.NumberOfAttempts < m_maxLoginAttemptsInWindow);
            }
        }
    }
}