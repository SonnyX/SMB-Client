/* Copyright (C) 2017-2018 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using SMBLibrary.Authentication.GssApi;
using SMBLibrary.Authentication.NTLM;
using Utilities;

namespace SMBLibrary.Client
{
    public class NtlmAuthenticationHelper
    {
        public static byte[]? GetNegotiateMessage(byte[] securityBlob, string domainName, AuthenticationMethod authenticationMethod)
        {
            bool useGssapi = false;
            if (securityBlob.Length > 0)
            {
                SimpleProtectedNegotiationTokenInit? inputToken = null;
                try
                {
                    inputToken = SimpleProtectedNegotiationToken.ReadToken(securityBlob, 0, true) as SimpleProtectedNegotiationTokenInit;
                }
                catch
                {
                    // ignored
                }

                if (inputToken == null || !ContainsMechanism(inputToken, GssProvider.NtlmSspIdentifier))
                {
                    return null;
                }
                useGssapi = true;
            }

            NegotiateMessage negotiateMessage = new NegotiateMessage
            {
                NegotiateFlags = NegotiateFlags.UnicodeEncoding |
                                              NegotiateFlags.OEMEncoding |
                                              NegotiateFlags.Sign |
                                              NegotiateFlags.NTLMSessionSecurity |
                                              NegotiateFlags.DomainNameSupplied |
                                              NegotiateFlags.WorkstationNameSupplied |
                                              NegotiateFlags.AlwaysSign |
                                              NegotiateFlags.Version |
                                              NegotiateFlags.Use128BitEncryption |
                                              NegotiateFlags.KeyExchange |
                                              NegotiateFlags.Use56BitEncryption
            };

            if (authenticationMethod == AuthenticationMethod.NtlmV1)
            {
                negotiateMessage.NegotiateFlags |= NegotiateFlags.LanManagerSessionKey;
            }
            else
            {
                negotiateMessage.NegotiateFlags |= NegotiateFlags.ExtendedSessionSecurity;
            }

            negotiateMessage.Version = NtlmVersion.Server2003;
            negotiateMessage.DomainName = domainName;
            negotiateMessage.Workstation = Environment.MachineName;
            if (!useGssapi)
                return negotiateMessage.GetBytes();

            SimpleProtectedNegotiationTokenInit outputToken = new SimpleProtectedNegotiationTokenInit
            {
                MechanismTypeList = new List<byte[]>
                {
                    GssProvider.NtlmSspIdentifier
                },
                MechanismToken = negotiateMessage.GetBytes()
            };
            return outputToken.GetBytes(true);

        }

        public static byte[]? GetAuthenticateMessage(byte[] securityBlob, string domainName, string userName, string password, AuthenticationMethod authenticationMethod, out byte[]? sessionKey)
        {
            sessionKey = null;
            bool useGssApi = false;
            SimpleProtectedNegotiationTokenResponse? inputToken = null;
            try
            {
                inputToken = SimpleProtectedNegotiationToken.ReadToken(securityBlob, 0, false) as SimpleProtectedNegotiationTokenResponse;
            }
            catch
            {
                // ignored
            }

            ChallengeMessage? challengeMessage;
            if (inputToken != null)
            {
                challengeMessage = GetChallengeMessage(inputToken.ResponseToken);
                useGssApi = true;
            }
            else
            {
                challengeMessage = GetChallengeMessage(securityBlob);
            }

            if (challengeMessage == null)
            {
                return null;
            }

            DateTime time = DateTime.UtcNow;
            byte[] clientChallenge = new byte[8];
            new Random().NextBytes(clientChallenge);

            AuthenticateMessage authenticateMessage = new AuthenticateMessage
            {
                // https://msdn.microsoft.com/en-us/library/cc236676.aspx
                NegotiateFlags = NegotiateFlags.Sign |
                                                 NegotiateFlags.NTLMSessionSecurity |
                                                 NegotiateFlags.AlwaysSign |
                                                 NegotiateFlags.Version |
                                                 NegotiateFlags.Use128BitEncryption |
                                                 NegotiateFlags.Use56BitEncryption
            };
            if ((challengeMessage.NegotiateFlags & NegotiateFlags.UnicodeEncoding) > 0)
            {
                authenticateMessage.NegotiateFlags |= NegotiateFlags.UnicodeEncoding;
            }
            else
            {
                authenticateMessage.NegotiateFlags |= NegotiateFlags.OEMEncoding;
            }

            if ((challengeMessage.NegotiateFlags & NegotiateFlags.KeyExchange) > 0)
            {
                authenticateMessage.NegotiateFlags |= NegotiateFlags.KeyExchange;
            }

            if (authenticationMethod == AuthenticationMethod.NtlmV1)
            {
                authenticateMessage.NegotiateFlags |= NegotiateFlags.LanManagerSessionKey;
            }
            else
            {
                authenticateMessage.NegotiateFlags |= NegotiateFlags.ExtendedSessionSecurity;
            }

            authenticateMessage.UserName = userName;
            authenticateMessage.DomainName = domainName;
            authenticateMessage.WorkStation = Environment.MachineName;
            byte[] sessionBaseKey;
            byte[] keyExchangeKey;
            if (authenticationMethod == AuthenticationMethod.NtlmV1 || authenticationMethod == AuthenticationMethod.NtlmV1ExtendedSessionSecurity)
            {
                if (authenticationMethod == AuthenticationMethod.NtlmV1)
                {
                    authenticateMessage.LmChallengeResponse = NtlmCryptography.ComputeLMv1Response(challengeMessage.ServerChallenge, password);
                    authenticateMessage.NtChallengeResponse = NtlmCryptography.ComputeNTLMv1Response(challengeMessage.ServerChallenge, password);
                }
                else // NtlmV1ExtendedSessionSecurity
                {
                    authenticateMessage.LmChallengeResponse = ByteUtils.Concatenate(clientChallenge, new byte[16]);
                    authenticateMessage.NtChallengeResponse = NtlmCryptography.ComputeNTLMv1ExtendedSessionSecurityResponse(challengeMessage.ServerChallenge, clientChallenge, password);
                }
                // https://msdn.microsoft.com/en-us/library/cc236699.aspx
                sessionBaseKey = new MD4().GetByteHashFromBytes(NtlmCryptography.NTOWFv1(password));
                byte[] lmowf = NtlmCryptography.LMOWFv1(password);
                keyExchangeKey = NtlmCryptography.KXKey(sessionBaseKey, authenticateMessage.NegotiateFlags, authenticateMessage.LmChallengeResponse, challengeMessage.ServerChallenge, lmowf);
            }
            else // NtlmV2
            {
                NTLMv2ClientChallenge clientChallengeStructure = new NTLMv2ClientChallenge(time, clientChallenge, challengeMessage.TargetInfo);
                byte[] clientChallengeStructurePadded = clientChallengeStructure.GetBytesPadded();
                byte[] ntProofStr = NtlmCryptography.ComputeNTLMv2Proof(challengeMessage.ServerChallenge, clientChallengeStructurePadded, password, userName, domainName);

                authenticateMessage.LmChallengeResponse = NtlmCryptography.ComputeLMv2Response(challengeMessage.ServerChallenge, clientChallenge, password, userName, challengeMessage.TargetName);
                authenticateMessage.NtChallengeResponse = ByteUtils.Concatenate(ntProofStr, clientChallengeStructurePadded);

                // https://msdn.microsoft.com/en-us/library/cc236700.aspx
                byte[] responseKeyNT = NtlmCryptography.NTOWFv2(password, userName, domainName);
                using HMACMD5 md5 = new HMACMD5(responseKeyNT);
                sessionBaseKey = md5.ComputeHash(ntProofStr);
                keyExchangeKey = sessionBaseKey;
            }
            authenticateMessage.Version = NtlmVersion.Server2003;

            // https://msdn.microsoft.com/en-us/library/cc236676.aspx
            if ((challengeMessage.NegotiateFlags & NegotiateFlags.KeyExchange) > 0)
            {
                sessionKey = new byte[16];
                new Random().NextBytes(sessionKey);
                authenticateMessage.EncryptedRandomSessionKey = RC4.Encrypt(keyExchangeKey, sessionKey);
            }
            else
            {
                sessionKey = keyExchangeKey;
            }

            if (!useGssApi)
                return authenticateMessage.GetBytes();

            SimpleProtectedNegotiationTokenResponse outputToken = new SimpleProtectedNegotiationTokenResponse
            {
                ResponseToken = authenticateMessage.GetBytes()
            };
            return outputToken.GetBytes();

        }

        private static ChallengeMessage? GetChallengeMessage(byte[] messageBytes)
        {
            if (!AuthenticationMessageUtils.IsSignatureValid(messageBytes))
                return null;

            MessageTypeName messageType = AuthenticationMessageUtils.GetMessageType(messageBytes);
            if (messageType != MessageTypeName.Challenge)
                return null;

            try
            {
                return new ChallengeMessage(messageBytes);
            }
            catch
            {
                return null;
            }
        }

        private static bool ContainsMechanism(SimpleProtectedNegotiationTokenInit token, byte[] mechanismIdentifier)
        {
            return token.MechanismTypeList.Any(t => ByteUtils.AreByteArraysEqual(t, mechanismIdentifier));
        }
    }
}