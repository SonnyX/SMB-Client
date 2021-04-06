/* Copyright (C) 2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Security.Cryptography;
using Utilities;
using AesCcm = Utilities.AesCcm;

namespace SMBLibrary.SMB2
{
    public class SMB2Cryptography
    {
        private const int AesCcmNonceLength = 11;

        public static byte[] CalculateSignature(byte[] signingKey, SMB2Dialect dialect, byte[] buffer, int offset, int paddedLength)
        {
            if (dialect != SMB2Dialect.SMB202 && dialect != SMB2Dialect.SMB210)
                return AesCmac.CalculateAesCmac(signingKey, buffer, offset, paddedLength);

            using HMACSHA256 sha256 = new HMACSHA256(signingKey);
            return sha256.ComputeHash(buffer, offset, paddedLength);
        }

        public static byte[] GenerateSigningKey(byte[] sessionKey, SMB2Dialect dialect, byte[]? preauthIntegrityHashValue)
        {
            if (dialect == SMB2Dialect.SMB202 || dialect == SMB2Dialect.SMB210)
            {
                return sessionKey;
            }

            if (dialect == SMB2Dialect.SMB311 && preauthIntegrityHashValue == null)
            {
                throw new ArgumentNullException(nameof(preauthIntegrityHashValue));
            }

            string labelString = (dialect == SMB2Dialect.SMB311) ? "SMBSigningKey" : "SMB2AESCMAC";
            byte[] label = GetNullTerminatedAnsiString(labelString);
            byte[] context = (dialect == SMB2Dialect.SMB311) ? preauthIntegrityHashValue! : GetNullTerminatedAnsiString("SmbSign");

            using HMACSHA256 hmac = new HMACSHA256(sessionKey);
            return SP800_1008.DeriveKey(hmac, label, context, 128);
        }

        public static byte[] GenerateClientEncryptionKey(byte[] sessionKey, SMB2Dialect dialect, byte[] preauthIntegrityHashValue)
        {
            if (dialect == SMB2Dialect.SMB311 && preauthIntegrityHashValue == null)
            {
                throw new ArgumentNullException(nameof(preauthIntegrityHashValue));
            }

            string labelString = (dialect == SMB2Dialect.SMB311) ? "SMBC2SCipherKey" : "SMB2AESCCM";
            byte[] label = GetNullTerminatedAnsiString(labelString);
            byte[] context = (dialect == SMB2Dialect.SMB311) ? preauthIntegrityHashValue : GetNullTerminatedAnsiString("ServerIn ");

            using HMACSHA256 hmac = new HMACSHA256(sessionKey);
            return SP800_1008.DeriveKey(hmac, label, context, 128);
        }

        public static byte[] GenerateClientDecryptionKey(byte[] sessionKey, SMB2Dialect dialect, byte[]? preauthIntegrityHashValue)
        {
            if (dialect == SMB2Dialect.SMB311 && preauthIntegrityHashValue == null)
            {
                throw new ArgumentNullException(nameof(preauthIntegrityHashValue));
            }

            string labelString = (dialect == SMB2Dialect.SMB311) ? "SMBS2CCipherKey" : "SMB2AESCCM";
            byte[] label = GetNullTerminatedAnsiString(labelString);
            byte[] context = (dialect == SMB2Dialect.SMB311) ? preauthIntegrityHashValue! : GetNullTerminatedAnsiString("ServerOut");

            using HMACSHA256 hmac = new HMACSHA256(sessionKey);
            return SP800_1008.DeriveKey(hmac, label, context, 128);
        }

        /// <summary>
        /// Encyrpt message and prefix with SMB2 TransformHeader
        /// </summary>
        public static byte[] TransformMessage(byte[] key, byte[] message, ulong sessionID)
        {
            byte[] nonce = GenerateAesCcmNonce();
            byte[] encryptedMessage = EncryptMessage(key, nonce, message, sessionID, out byte[] signature);
            SMB2TransformHeader transformHeader = CreateTransformHeader(nonce, message.Length, sessionID);
            transformHeader.Signature = signature;

            byte[] buffer = new byte[SMB2TransformHeader.Length + message.Length];
            transformHeader.WriteBytes(buffer, 0);
            ByteWriter.WriteBytes(buffer, SMB2TransformHeader.Length, encryptedMessage);
            return buffer;
        }

        public static byte[] EncryptMessage(byte[] key, byte[] nonce, byte[] message, ulong sessionID, out byte[] signature)
        {
            SMB2TransformHeader transformHeader = CreateTransformHeader(nonce, message.Length, sessionID);
            byte[] associatedata = transformHeader.GetAssociatedData();
            return AesCcm.Encrypt(key, nonce, message, associatedata, SMB2TransformHeader.SignatureLength, out signature);
        }

        public static byte[] DecryptMessage(byte[] key, SMB2TransformHeader transformHeader, byte[] encryptedMessage)
        {
            byte[] associatedData = transformHeader.GetAssociatedData();
            byte[] aesCcmNonce = ByteReader.ReadBytes(transformHeader.Nonce, 0, AesCcmNonceLength);
            return AesCcm.DecryptAndAuthenticate(key, aesCcmNonce, encryptedMessage, associatedData, transformHeader.Signature);
        }

        private static SMB2TransformHeader CreateTransformHeader(byte[] nonce, int originalMessageLength, ulong sessionID)
        {
            byte[] nonceWithPadding = new byte[SMB2TransformHeader.NonceLength];
            Array.Copy(nonce, nonceWithPadding, nonce.Length);

            SMB2TransformHeader transformHeader = new SMB2TransformHeader {Nonce = nonceWithPadding, OriginalMessageSize = (uint) originalMessageLength, Flags = SMB2TransformHeaderFlags.Encrypted, SessionId = sessionID};

            return transformHeader;
        }

        private static byte[] GenerateAesCcmNonce()
        {
            byte[] aesCcmNonce = new byte[AesCcmNonceLength];
            new Random().NextBytes(aesCcmNonce);
            return aesCcmNonce;
        }

        private static byte[] GetNullTerminatedAnsiString(string value)
        {
            byte[] result = new byte[value.Length + 1];
            ByteWriter.WriteNullTerminatedAnsiString(result, 0, value);
            return result;
        }
    }
}