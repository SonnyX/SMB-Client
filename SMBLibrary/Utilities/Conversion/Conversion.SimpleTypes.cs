/* Copyright (C) 2005-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;

namespace Utilities
{
    public class Conversion
    {
        public static bool ToBoolean(object obj)
        {
            return ToBoolean(obj, false);
        }

        public static bool ToBoolean(object obj, bool defaultValue)
        {
            bool result = defaultValue;
            if (obj != null)
            {
                try
                {
                    result = Convert.ToBoolean(obj);
                }
                catch
                { }
            }
            return result;
        }
    }
}