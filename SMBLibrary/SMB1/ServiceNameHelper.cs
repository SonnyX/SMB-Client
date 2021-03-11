/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary.SMB1
{
    public class ServiceNameHelper
    {
        public static string GetServiceString(ServiceName serviceName)
        {
            return serviceName switch
            {
                ServiceName.DiskShare => "A:",
                ServiceName.PrinterShare => "LPT1:",
                ServiceName.NamedPipe => "IPC",
                ServiceName.SerialCommunicationsDevice => "COMM",
                _ => "?????"
            };
        }

        public static ServiceName GetServiceName(string serviceString)
        {
            return serviceString switch
            {
                "A:" => ServiceName.DiskShare,
                "LPT1:" => ServiceName.PrinterShare,
                "IPC" => ServiceName.NamedPipe,
                "COMM" => ServiceName.SerialCommunicationsDevice,
                _ => ServiceName.AnyType
            };
        }
    }
}