/* Copyright (C) 2012-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;

namespace Utilities
{
    public class KeyValuePairList<TKey, TValue> : List<KeyValuePair<TKey, TValue>>
    {
        public int IndexOfKey(TKey key)
        {
            for (int index = 0; index < Count; index++)
            {
                if (this[index].Key.Equals(key))
                {
                    return index;
                }
            }

            return -1;
        }

        public void Add(TKey key, TValue value)
        {
            Add(new KeyValuePair<TKey, TValue>(key, value));
        }
    }
}